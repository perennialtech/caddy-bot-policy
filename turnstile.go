package botpolicy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	// siteverifyURL is Cloudflare's Turnstile token validation endpoint.
	siteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	// turnstileAction is sent as the widget's data-action and checked in the
	// siteverify response, so a token minted for some other form on the same
	// site key cannot be redeemed for a clearance.
	turnstileAction = "bot_policy_clearance"

	// turnstileTokenField is the form field the widget writes its token into.
	turnstileTokenField = "cf-turnstile-response"

	// maxTurnstileToken is the longest token Cloudflare issues.
	maxTurnstileToken = 2048

	defaultClearanceTTL    = 30 * 24 * time.Hour
	defaultClearanceCookie = "bp_clearance"
	defaultVerifyPath      = "/.bot-policy/turnstile"

	// clearanceKeyLabel separates the HMAC key derived from the Turnstile
	// secret from any other use of that secret.
	clearanceKeyLabel = "caddy-bot-policy/turnstile/clearance/v1"
)

// Turnstile is an HTTP middleware that requires a Cloudflare Turnstile
// clearance before letting a request through.
//
// A request carrying a valid clearance cookie goes straight to the next
// handler. Any other request is answered with a challenge page hosting the
// Turnstile widget. The widget's token is posted to VerifyPath, checked
// against Cloudflare's siteverify endpoint, and on success the visitor gets
// a signed clearance cookie and is redirected back to the page they asked
// for. A token that fails verification is answered with a 403 and no cookie.
//
// The cookie is stateless: it carries the time it was issued and an
// HMAC-SHA256 over that time, the site's hostname and, optionally, the
// client's JA4 fingerprint. Nothing is stored server-side, so it works
// unchanged across restarts and across several Caddy instances that share
// the same keys.
//
//	turnstile {
//		site_key         {env.TURNSTILE_SITE_KEY}
//		secret_key       {env.TURNSTILE_SECRET_KEY}
//		clearance_ttl    30d
//		bind_fingerprint ja4
//	}
type Turnstile struct {
	// SiteKey is the public key of the Turnstile widget. Required.
	SiteKey string `json:"site_key,omitempty"`

	// SecretKey is the widget's secret key, used to call siteverify.
	// Required. Placeholders such as {env.TURNSTILE_SECRET_KEY} are
	// expanded at provision time.
	SecretKey string `json:"secret_key,omitempty"`

	// ClearanceKey signs the clearance cookie. Optional: by default a key is
	// derived from SecretKey, which means rotating the Turnstile secret
	// also invalidates every clearance. If set it must be at least 32
	// bytes. Placeholders are expanded at provision time.
	ClearanceKey string `json:"clearance_key,omitempty"`

	// ClearanceTTL is how long a clearance stays valid after it is issued.
	// Defaults to 30 days.
	ClearanceTTL caddy.Duration `json:"clearance_ttl,omitempty"`

	// CookieName is the name of the clearance cookie. Defaults to
	// "bp_clearance".
	CookieName string `json:"cookie_name,omitempty"`

	// VerifyPath is the path the challenge page posts the Turnstile token
	// to. Defaults to "/.bot-policy/turnstile". POST requests to this path
	// are handled here and never reach the next handler.
	VerifyPath string `json:"verify_path,omitempty"`

	// BindFingerprintVar, if set, names the http.vars.* key holding the
	// client's JA4 fingerprint (normally "ja4", published by the ja4
	// handler). The clearance is then only accepted from a client with the
	// same fingerprint it was issued to, so a cookie lifted from a browser
	// and replayed from a script with a different TLS stack is rejected.
	BindFingerprintVar string `json:"bind_fingerprint_var,omitempty"`

	key        []byte
	ttl        time.Duration
	siteverify string
	client     *http.Client
	now        func() time.Time
	logger     *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Turnstile) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.turnstile",
		New: func() caddy.Module { return new(Turnstile) },
	}
}

// Provision sets up ts.
func (ts *Turnstile) Provision(ctx caddy.Context) error {
	ts.logger = ctx.Logger()

	repl := caddy.NewReplacer()
	ts.SiteKey = repl.ReplaceKnown(ts.SiteKey, "")
	ts.SecretKey = repl.ReplaceKnown(ts.SecretKey, "")
	ts.ClearanceKey = repl.ReplaceKnown(ts.ClearanceKey, "")

	if ts.SiteKey == "" {
		return errors.New("turnstile: site_key is required")
	}
	if ts.SecretKey == "" {
		return errors.New("turnstile: secret_key is required")
	}

	switch {
	case ts.ClearanceKey == "":
		mac := hmac.New(sha256.New, []byte(ts.SecretKey))
		mac.Write([]byte(clearanceKeyLabel))
		ts.key = mac.Sum(nil)
	case len(ts.ClearanceKey) < 32:
		return errors.New("turnstile: clearance_key must be at least 32 bytes")
	default:
		ts.key = []byte(ts.ClearanceKey)
	}

	ts.ttl = time.Duration(ts.ClearanceTTL)
	if ts.ttl == 0 {
		ts.ttl = defaultClearanceTTL
	}
	if ts.ttl < 0 {
		return errors.New("turnstile: clearance_ttl must be positive")
	}

	if ts.CookieName == "" {
		ts.CookieName = defaultClearanceCookie
	}
	if ts.VerifyPath == "" {
		ts.VerifyPath = defaultVerifyPath
	}
	if !strings.HasPrefix(ts.VerifyPath, "/") {
		return fmt.Errorf("turnstile: verify_path must start with '/', got %q", ts.VerifyPath)
	}

	if ts.siteverify == "" {
		ts.siteverify = siteverifyURL
	}
	if ts.client == nil {
		ts.client = &http.Client{Timeout: 10 * time.Second}
	}
	if ts.now == nil {
		ts.now = time.Now
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (ts *Turnstile) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method == http.MethodPost && r.URL.Path == ts.VerifyPath {
		return ts.verify(w, r)
	}
	if c, err := r.Cookie(ts.CookieName); err == nil && ts.validClearance(c.Value, r) {
		return next.ServeHTTP(w, r)
	}
	return ts.challenge(w, r)
}

// mintClearance returns a clearance cookie value issued at the given time.
func (ts *Turnstile) mintClearance(issued time.Time, r *http.Request) string {
	iat := strconv.FormatInt(issued.Unix(), 10)
	return "1." + iat + "." + base64.RawURLEncoding.EncodeToString(ts.clearanceMAC(iat, r))
}

// validClearance reports whether value is a clearance this handler issued
// for this host (and fingerprint, if bound) that has not expired.
func (ts *Turnstile) validClearance(value string, r *http.Request) bool {
	version, rest, ok := strings.Cut(value, ".")
	if !ok || version != "1" {
		return false
	}
	iat, sig, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, ts.clearanceMAC(iat, r)) {
		return false
	}
	// The signature is checked first, so iat is our own value from here on.
	secs, err := strconv.ParseInt(iat, 10, 64)
	if err != nil {
		return false
	}
	age := ts.now().Sub(time.Unix(secs, 0))
	// The issue time is compared with the TTL configured now rather than
	// one baked into the cookie, so shortening clearance_ttl takes effect
	// immediately. The small negative allowance covers clock steps between
	// instances.
	return age > -time.Minute && age < ts.ttl
}

func (ts *Turnstile) clearanceMAC(iat string, r *http.Request) []byte {
	mac := hmac.New(sha256.New, ts.key)
	mac.Write([]byte("1\x00"))
	mac.Write([]byte(iat))
	mac.Write([]byte{0})
	mac.Write([]byte(requestHostname(r)))
	mac.Write([]byte{0})
	if ts.BindFingerprintVar != "" {
		fp, _ := caddyhttp.GetVar(r.Context(), ts.BindFingerprintVar).(string)
		mac.Write([]byte(fp))
	}
	return mac.Sum(nil)
}

var challengeTemplate = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Checking your browser</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;background:#fafafa;color:#222}
@media (prefers-color-scheme:dark){body{background:#151515;color:#ddd}}
main{text-align:center;padding:16px}
button{margin-top:16px;padding:8px 20px;font:inherit;cursor:pointer}
</style>
</head>
<body>
<main>
<h1>Checking your browser</h1>
<p>This only takes a moment.</p>
<form id="bp-turnstile" method="POST" action="{{.VerifyPath}}">
<input type="hidden" name="return" value="{{.Return}}">
<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-action="{{.Action}}" data-callback="bpTurnstileDone"></div>
<noscript><p>JavaScript is required to continue.</p></noscript>
<button type="submit">Continue</button>
</form>
</main>
<script>function bpTurnstileDone(){document.getElementById("bp-turnstile").submit()}</script>
</body>
</html>
`))

// challenge serves the Turnstile challenge page.
//
// It is sent with a 403 so that crawlers and API clients do not mistake it
// for the page they asked for, and is never cached.
func (ts *Turnstile) challenge(w http.ResponseWriter, r *http.Request) error {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return nil
	}
	return challengeTemplate.Execute(w, struct {
		VerifyPath, Return, SiteKey, Action string
	}{ts.VerifyPath, r.URL.RequestURI(), ts.SiteKey, turnstileAction})
}

// siteverifyResult is the part of Cloudflare's siteverify response that is
// checked.
type siteverifyResult struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

// verify redeems the posted Turnstile token and, if Cloudflare accepts it,
// issues a clearance cookie and redirects back to the original page.
func (ts *Turnstile) verify(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		return ts.reject(w, r, "unreadable form", nil)
	}
	token := r.PostForm.Get(turnstileTokenField)
	if token == "" || len(token) > maxTurnstileToken {
		return ts.reject(w, r, "missing or oversized token", nil)
	}

	result, err := ts.siteverifyToken(r.Context(), token, r)
	if err != nil {
		ts.logger.Error("turnstile siteverify failed", zap.Error(err))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "5")
		http.Error(w, "503 Service Unavailable: verification is temporarily unavailable, please try again", http.StatusServiceUnavailable)
		return nil
	}

	host := requestHostname(r)
	switch {
	case !result.Success:
		return ts.reject(w, r, "token rejected", result)
	case result.Action != turnstileAction:
		return ts.reject(w, r, "action mismatch", result)
	case !strings.EqualFold(result.Hostname, host):
		return ts.reject(w, r, "hostname mismatch", result)
	}

	now := ts.now()
	http.SetCookie(w, &http.Cookie{
		Name:     ts.CookieName,
		Value:    ts.mintClearance(now, r),
		Path:     "/",
		Expires:  now.Add(ts.ttl),
		MaxAge:   int(ts.ttl / time.Second),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	ts.logger.Debug("turnstile clearance issued",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", host),
	)

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeReturnPath(r.PostForm.Get("return")), http.StatusSeeOther)
	return nil
}

func (ts *Turnstile) siteverifyToken(ctx context.Context, token string, r *http.Request) (*siteverifyResult, error) {
	form := url.Values{
		"secret":   {ts.SecretKey},
		"response": {token},
	}
	// The client IP as Caddy resolved it, which honours trusted_proxies.
	if ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ip != "" {
		form.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.siteverify, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("siteverify returned HTTP %d", resp.StatusCode)
	}

	var result siteverifyResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding siteverify response: %w", err)
	}
	return &result, nil
}

// reject answers a failed verification with a 403 and no clearance. The
// visitor is not remembered: loading the page again serves a fresh challenge.
func (ts *Turnstile) reject(w http.ResponseWriter, r *http.Request, reason string, result *siteverifyResult) error {
	id := newBlockID("ts-")
	fields := []zap.Field{
		zap.String("block_id", id),
		zap.String("reason", reason),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
	}
	if result != nil {
		fields = append(fields,
			zap.Strings("error_codes", result.ErrorCodes),
			zap.String("token_hostname", result.Hostname),
			zap.String("token_action", result.Action),
		)
	}
	ts.logger.Info("turnstile verification failed", fields...)

	w.Header().Set("X-Block-Id", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "403 Forbidden: verification failed (block id: %s)\n", id)
	return nil
}

// safeReturnPath returns p if it is a path on this site, and "/" otherwise,
// so the verify endpoint cannot be used as an open redirect.
func safeReturnPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return p
}

// requestHostname is the request's Host without any port, lowercased. It is
// compared with the hostname siteverify reports the token was solved on.
func requestHostname(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Turnstile)(nil)
	_ caddyhttp.MiddlewareHandler = (*Turnstile)(nil)
)
