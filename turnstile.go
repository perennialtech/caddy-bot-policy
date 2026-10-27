package botpolicy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// siteverifyURL is Cloudflare's Turnstile token validation endpoint. It is a
// variable only so that tests can point it at a stand-in server.
var siteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

const (
	// turnstileAction is sent as the widget's data-action and checked in the
	// siteverify response, so a token minted for some other form on the same
	// site key cannot be redeemed for a clearance.
	turnstileAction = "bot_policy_clearance"

	// turnstileTokenField is the form field the widget writes its token into.
	turnstileTokenField = "cf-turnstile-response"

	// turnstileMarkerField marks a POST as the challenge page's own
	// submission, as opposed to some other form posted by an uncleared
	// client.
	turnstileMarkerField = "__bp_turnstile"

	// maxTurnstileToken is the longest token Cloudflare issues.
	maxTurnstileToken = 2048

	defaultClearanceTTL    = 30 * 24 * time.Hour
	defaultClearanceCookie = "bp_clearance"

	// defaultMaxPendingVerifications bounds concurrent siteverify calls per
	// handler. It is not a rate limit, only a cap on the goroutines and
	// outbound connections an unauthenticated flood can tie up; see the
	// README for per-client rate limiting.
	defaultMaxPendingVerifications = 64

	// Browsers cap cookie lifetimes at 400 days (RFC 6265bis), and below a
	// minute a clearance would expire before the redirect lands.
	minClearanceTTL = time.Minute
	maxClearanceTTL = 400 * 24 * time.Hour

	// clearanceKeyLabel separates the HMAC key derived from the Turnstile
	// secret from any other use of that secret.
	clearanceKeyLabel = "caddy-bot-policy/turnstile/clearance/v1"
	// Cookie names must differ across signing configurations and, when
	// binding is enabled, across complete fingerprints. Otherwise visiting
	// one protected route/profile overwrites another route/profile's cookie.
	clearanceCookieLabel = "caddy-bot-policy/turnstile/cookie/v3\x00"
	// Version 3 also authenticates the configured cookie prefix. Older
	// clearances cannot cross into policies with a different cookie_name.
	clearanceVersion = "3"
)

var varNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Turnstile is an HTTP middleware that requires a Cloudflare Turnstile
// clearance before letting a request through.
//
// A request carrying a valid clearance cookie goes straight to the next
// handler. Any other request is answered with a challenge page hosting the
// Turnstile widget. The solved widget posts its token back to the URL the
// visitor originally asked for, where this handler redeems it with
// Cloudflare's siteverify endpoint; on success the visitor gets a signed
// clearance cookie and is redirected to that same URL with a GET. A token
// that fails verification is answered with a 403 and no cookie.
//
// The cookie is stateless: it carries the time it was issued and an
// HMAC-SHA256 over that time, the policy identity, the site's hostname
// and, optionally, the client's JA4 fingerprint. Nothing is stored server-
// side, so it works unchanged across restarts and across several Caddy
// instances that share the same keys.
//
// It is a bearer credential: anything that presents the cookie (with the
// same fingerprint, if bound) is treated as having solved the challenge.
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
	// Defaults to 30 days; must be between one minute and 400 days.
	ClearanceTTL caddy.Duration `json:"clearance_ttl,omitempty"`

	// CookieName is the prefix of the clearance cookie name. The final name
	// also carries a stable, keyed namespace for this configuration and,
	// when binding is enabled, the complete fingerprint.
	CookieName string `json:"cookie_name,omitempty"`

	// BindFingerprintVar, if set, names the http.vars.* key holding the
	// client's JA4 fingerprint (normally "ja4", published by the ja4
	// handler). A clearance is then only issued to a request that has a
	// fingerprint, and only accepted from a client with the same
	// fingerprint. Requests without one are never cleared.
	BindFingerprintVar string `json:"bind_fingerprint_var,omitempty"`

	// MaxPendingVerifications caps how many siteverify calls this handler
	// has in flight at once. Submissions beyond it get a 503 without
	// calling Cloudflare. Defaults to 64.
	MaxPendingVerifications int `json:"max_pending_verifications,omitempty"`

	// AllowInsecureCookie permits a clearance cookie without Secure on
	// HTTP-only development sites. Never enable it on a public hostname.
	// The default is Secure even when Caddy receives HTTP from a TLS proxy.
	AllowInsecureCookie bool `json:"allow_insecure_cookie,omitempty"`

	key     []byte
	ttl     time.Duration
	pending chan struct{}
	client  *http.Client
	now     func() time.Time
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Turnstile) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.turnstile",
		New: func() caddy.Module { return new(Turnstile) },
	}
}

// Provision sets up ts and validates its configuration, so that a mistake
// is a config error at load time rather than a broken challenge at runtime.
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
	if isDummySecret(ts.SecretKey) {
		ts.logger.Warn("turnstile is using one of Cloudflare's public testing secret keys; " +
			"every visitor will get the same result and hostname/action are not checked. Do not use this in production")
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
	if ts.ttl < minClearanceTTL || ts.ttl > maxClearanceTTL {
		return fmt.Errorf("turnstile: clearance_ttl must be between %v and 400 days, got %v", minClearanceTTL, ts.ttl)
	}

	if ts.CookieName == "" {
		ts.CookieName = defaultClearanceCookie
	}
	// The generated suffix uses only cookie-safe base64url characters.
	if err := (&http.Cookie{Name: ts.CookieName, Value: "x"}).Valid(); err != nil {
		return fmt.Errorf("turnstile: invalid cookie_name %q: %v", ts.CookieName, err)
	}

	if ts.BindFingerprintVar != "" && !varNamePattern.MatchString(ts.BindFingerprintVar) {
		return fmt.Errorf("turnstile: invalid bind_fingerprint variable name %q", ts.BindFingerprintVar)
	}

	if ts.MaxPendingVerifications == 0 {
		ts.MaxPendingVerifications = defaultMaxPendingVerifications
	}
	if ts.MaxPendingVerifications < 1 {
		return errors.New("turnstile: max_pending_verifications must be at least 1")
	}
	ts.pending = make(chan struct{}, ts.MaxPendingVerifications)

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
	if ts.cleared(r) {
		return next.ServeHTTP(w, r)
	}
	if r.Method == http.MethodPost && isFormPost(r) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err == nil && r.PostForm.Get(turnstileMarkerField) != "" {
			return ts.verify(w, r)
		}
		// Some other form posted by a client without clearance. It would
		// be challenged anyway, so consuming its body is harmless.
	}
	return ts.challenge(w, r)
}

// fingerprint returns the bound fingerprint for r and whether binding is
// on. With binding on, an empty fingerprint means r cannot be cleared.
func (ts *Turnstile) fingerprint(r *http.Request) (string, bool) {
	if ts.BindFingerprintVar == "" {
		return "", false
	}
	fp, _ := caddyhttp.GetVar(r.Context(), ts.BindFingerprintVar).(string)
	return fp, true
}

// writeMACField uses length-prefix framing so the policy fields cannot be
// reinterpreted by moving delimiters between them.
func writeMACField(mac hash.Hash, field string) {
	mac.Write([]byte(strconv.Itoa(len(field))))
	mac.Write([]byte(":"))
	mac.Write([]byte(field))
}

// writePolicyIdentity binds the widget, fingerprint variable and cookie
// prefix to each signed clearance, so copying a value to another policy's
// cookie name cannot bypass that policy. It excludes the verification secret
// so an explicit clearance_key survives secret_key rotation.
func (ts *Turnstile) writePolicyIdentity(mac hash.Hash) {
	writeMACField(mac, ts.SiteKey)
	writeMACField(mac, ts.BindFingerprintVar)
	writeMACField(mac, ts.CookieName)
}

// cookieName isolates different protection configurations, and (when bound)
// every distinct JA4, not just the transport. This prevents browsers that
// alternate TLS/ALPN profiles or protected routes from overwriting their
// previously solved clearances. Keyed names don't disclose the fingerprint.
func (ts *Turnstile) cookieName(fp string, bound bool) string {
	mac := hmac.New(sha256.New, ts.key)
	mac.Write([]byte(clearanceCookieLabel))
	ts.writePolicyIdentity(mac)
	if bound {
		mac.Write([]byte("bound\x00"))
		writeMACField(mac, fp)
	} else {
		mac.Write([]byte("unbound"))
	}
	return ts.CookieName + "_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func (ts *Turnstile) cleared(r *http.Request) bool {
	fp, bound := ts.fingerprint(r)
	if bound && fp == "" {
		return false
	}
	c, err := r.Cookie(ts.cookieName(fp, bound))
	return err == nil && ts.validClearance(c.Value, r)
}

// mintClearance returns a clearance cookie value issued at the given time.
func (ts *Turnstile) mintClearance(issued time.Time, r *http.Request) string {
	iat := strconv.FormatInt(issued.Unix(), 10)
	return clearanceVersion + "." + iat + "." + base64.RawURLEncoding.EncodeToString(ts.clearanceMAC(iat, r))
}

// validClearance reports whether value is a clearance this handler issued
// for this host (and fingerprint, if bound) that has not expired.
func (ts *Turnstile) validClearance(value string, r *http.Request) bool {
	if fp, bound := ts.fingerprint(r); bound && fp == "" {
		return false
	}
	version, rest, ok := strings.Cut(value, ".")
	if !ok || version != clearanceVersion {
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
	mac.Write([]byte(clearanceVersion + "\x00"))
	ts.writePolicyIdentity(mac)
	mac.Write([]byte(iat))
	mac.Write([]byte{0})
	mac.Write([]byte(requestHostname(r)))
	mac.Write([]byte{0})
	// The mode byte keeps bound and unbound clearances apart even if the
	// same key were used for both.
	if fp, bound := ts.fingerprint(r); bound {
		mac.Write([]byte("j"))
		mac.Write([]byte(fp))
	} else {
		mac.Write([]byte("-"))
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
<script nonce="{{.Nonce}}" src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style nonce="{{.Nonce}}">` + pageStyle + `</style>
</head>
<body>
<main>
<h1>Checking your browser</h1>
<p>This only takes a moment.</p>
<form id="bp-turnstile" method="POST" action="{{.Action}}">
<input type="hidden" name="` + turnstileMarkerField + `" value="1">
<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-action="{{.WidgetAction}}" data-callback="bpTurnstileDone"></div>
</form>
<noscript><p>JavaScript is required to continue.</p></noscript>
</main>
<script nonce="{{.Nonce}}">function bpTurnstileDone(){document.getElementById("bp-turnstile").submit()}</script>
</body>
</html>
`))

var statusTemplate = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">` + pageStyle + `</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p><a href="{{.Retry}}">Try again</a></p>
{{if .BlockID}}<p><small>Block ID: {{.BlockID}}</small></p>{{end}}
</main>
</body>
</html>
`))

const pageStyle = `body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;background:#fafafa;color:#222}
@media (prefers-color-scheme:dark){body{background:#151515;color:#ddd}a{color:#8ab4f8}}
main{text-align:center;padding:16px}`

// setPageHeaders sets the headers shared by every page this handler serves,
// and returns the CSP nonce for the page's own script and style.
//
// The page sets its own Content-Security-Policy, replacing any the site
// set earlier in the route (a header directive runs before this handler),
// because a site's policy is written for the site's pages and will usually
// block Turnstile. It follows Cloudflare's recommended nonce-based setup:
// the nonce is put on api.js, which propagates it to what it loads.
func setPageHeaders(w http.ResponseWriter) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	nonce := base64.RawURLEncoding.EncodeToString(b[:]) // CSP allows - and _; html/template would escape +

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "script-src 'nonce-"+nonce+"' 'strict-dynamic' https://challenges.cloudflare.com; "+
		"frame-src https://challenges.cloudflare.com; "+
		"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	return nonce
}

// challenge serves the Turnstile challenge page.
//
// It is sent with a 403 so that crawlers and API clients do not mistake it
// for the page they asked for, and is never cached. The form posts back to
// the URL the visitor originally requested, so the submission goes through
// the same routes and matchers as the request that was challenged, whatever
// rewrites happen along the way.
func (ts *Turnstile) challenge(w http.ResponseWriter, r *http.Request) error {
	nonce := setPageHeaders(w)
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return nil
	}
	return challengeTemplate.Execute(w, struct {
		Nonce, Action, SiteKey, WidgetAction string
	}{nonce, originalURI(r), ts.SiteKey, turnstileAction})
}

// siteverifyResult is the part of Cloudflare's siteverify response that is
// checked.
type siteverifyResult struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
	Metadata   struct {
		// ResultWithTestingKey is set when the secret is one of
		// Cloudflare's public testing keys. Those responses report the
		// hostname as example.com and carry no action.
		ResultWithTestingKey bool `json:"result_with_testing_key"`
	} `json:"metadata"`
}

// verify redeems the posted Turnstile token and, if Cloudflare accepts it,
// issues a clearance cookie and redirects back to the original page.
func (ts *Turnstile) verify(w http.ResponseWriter, r *http.Request) error {
	token := r.PostForm.Get(turnstileTokenField)
	if token == "" || len(token) > maxTurnstileToken {
		return ts.reject(w, r, "missing or oversized token", nil)
	}
	fp, bound := ts.fingerprint(r)
	if bound && fp == "" {
		// Checked before calling Cloudflare: there is nothing to bind to,
		// so no clearance could be issued anyway. This is almost always a
		// configuration problem (missing listener or packet conn wrapper,
		// or a var name that does not match the ja4 handler's).
		ts.logger.Warn("turnstile cannot issue a bound clearance: request has no fingerprint",
			zap.String("var_name", ts.BindFingerprintVar),
			zap.String("proto", r.Proto),
		)
		return ts.reject(w, r, "no fingerprint to bind", nil)
	}

	select {
	case ts.pending <- struct{}{}:
		defer func() { <-ts.pending }()
	default:
		ts.logger.Warn("turnstile verification refused: too many pending verifications",
			zap.Int("max_pending_verifications", ts.MaxPendingVerifications))
		return ts.unavailable(w, r)
	}

	result, err := ts.siteverifyToken(r.Context(), token, r)
	if err != nil {
		ts.logger.Error("turnstile siteverify failed", zap.Error(err))
		return ts.unavailable(w, r)
	}

	host := requestHostname(r)
	switch {
	case !result.Success:
		return ts.reject(w, r, "token rejected", result)
	case result.Metadata.ResultWithTestingKey:
		// Only a public testing secret produces this, and with one every
		// token passes regardless, so checking hostname and action would
		// only make the testing keys unusable.
		ts.logger.Warn("turnstile accepted a token from a testing key; hostname and action were not checked")
	case result.Action != turnstileAction:
		return ts.reject(w, r, "action mismatch", result)
	case !strings.EqualFold(result.Hostname, host):
		return ts.reject(w, r, "hostname mismatch", result)
	}

	now := ts.now()
	http.SetCookie(w, &http.Cookie{
		Name:     ts.cookieName(fp, bound),
		Value:    ts.mintClearance(now, r),
		Path:     "/",
		Expires:  now.Add(ts.ttl),
		MaxAge:   int(ts.ttl / time.Second),
		HttpOnly: true,
		Secure:   !ts.AllowInsecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	ts.logger.Debug("turnstile clearance issued",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", host),
	)

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, originalURI(r), http.StatusSeeOther)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, siteverifyURL, strings.NewReader(form.Encode()))
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
// visitor is not remembered; the page links back to the original URL, where
// a GET serves a fresh challenge.
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
	return ts.status(w, r, http.StatusForbidden, "Verification failed", "We couldn't verify your browser.", id)
}

// unavailable answers when verification could not be attempted: Cloudflare
// unreachable or too many verifications in flight. No clearance is issued,
// but this is not a block.
func (ts *Turnstile) unavailable(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Retry-After", "5")
	return ts.status(w, r, http.StatusServiceUnavailable, "Verification unavailable",
		"Verification is temporarily unavailable. Please try again in a few seconds.", "")
}

func (ts *Turnstile) status(w http.ResponseWriter, r *http.Request, code int, title, message, blockID string) error {
	nonce := setPageHeaders(w)
	w.WriteHeader(code)
	return statusTemplate.Execute(w, struct {
		Nonce, Title, Message, Retry, BlockID string
	}{nonce, title, message, originalURI(r), blockID})
}

// originalURI is the path and query the visitor actually requested, before
// any rewrite, try_files or handle_path changed r.URL. It is where the
// challenge form posts, where a successful verification redirects, and
// where "try again" links point.
func originalURI(r *http.Request) string {
	u := r.URL
	if or, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok && or.URL != nil {
		u = or.URL
	}
	return safeReturnPath(u.RequestURI())
}

// safeReturnPath returns p if it is a path on this site, and "/" otherwise,
// so that a crafted request line can never turn into an off-site redirect or
// form action.
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

func isFormPost(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/x-www-form-urlencoded"
}

// isDummySecret reports whether s is one of Cloudflare's published testing
// secret keys ("1x000...AA", "2x000...AA", "3x000...AA").
func isDummySecret(s string) bool {
	return len(s) == 35 && s[0] >= '1' && s[0] <= '3' && s[1] == 'x' &&
		strings.Trim(s[2:33], "0") == "" && s[33:] == "AA"
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
