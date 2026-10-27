package botpolicy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	testSiteKey   = "1x00000000000000000000AA"
	testSecretKey = "1x0000000000000000000000000000000AA"
	testHost      = "example.com"
	testFP        = "t13d1517h2_8daaf6152771_b6f405a00624"
)

// fakeSiteverify stands in for Cloudflare. It accepts exactly one token,
// "good", once, and reports the given hostname and action for it.
func fakeSiteverify(t *testing.T, hostname, action string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	var redeemed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("siteverify: %v", err)
		}
		if got := r.PostForm.Get("secret"); got != testSecretKey {
			t.Errorf("siteverify got secret %q", got)
		}
		res := siteverifyResult{Hostname: hostname, Action: action}
		switch {
		case r.PostForm.Get("response") != "good":
			res.ErrorCodes = []string{"invalid-input-response"}
		case redeemed.Swap(true):
			res.ErrorCodes = []string{"timeout-or-duplicate"}
		default:
			res.Success = true
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newTestTurnstile(t *testing.T, siteverify string, bind bool) *Turnstile {
	t.Helper()
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey, siteverify: siteverify}
	if bind {
		ts.BindFingerprintVar = "ja4"
	}
	if err := ts.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return ts
}

func newTurnstileRequest(method, target, fingerprint string, body url.Values) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Host = testHost
	req.TLS = &tls.ConnectionState{}
	vars := map[string]any{caddyhttp.ClientIPVarKey: "203.0.113.1"}
	if fingerprint != "" {
		vars["ja4"] = fingerprint
	}
	return req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
}

func serve(t *testing.T, ts *Turnstile, req *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	var reached bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		reached = true
		w.WriteHeader(http.StatusOK)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := ts.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	return rec, reached
}

func clearanceFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == defaultClearanceCookie {
			return c
		}
	}
	return nil
}

// TestTurnstileFullFlow walks a visitor through the whole thing: challenged,
// solves, gets a cookie, comes back with it and is let through.
func TestTurnstileFullFlow(t *testing.T) {
	srv, _ := fakeSiteverify(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, srv.URL, false)

	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodGet, "/articles?page=2", "", nil))
	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("no cookie: got %d (reached=%v), want a 403 challenge", rec.Code, reached)
	}
	page := rec.Body.String()
	for _, want := range []string{testSiteKey, turnstileAction, defaultVerifyPath, `value="/articles?page=2"`, "challenges.cloudflare.com/turnstile/v0/api.js"} {
		if !strings.Contains(page, want) {
			t.Errorf("challenge page is missing %q", want)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("challenge page must not be cacheable")
	}

	rec, reached = serve(t, ts, newTurnstileRequest(http.MethodPost, defaultVerifyPath, "", url.Values{
		turnstileTokenField: {"good"},
		"return":            {"/articles?page=2"},
	}))
	if reached || rec.Code != http.StatusSeeOther {
		t.Fatalf("verify: got %d (reached=%v), want 303", rec.Code, reached)
	}
	if loc := rec.Header().Get("Location"); loc != "/articles?page=2" {
		t.Errorf("verify redirected to %q, want the original page", loc)
	}
	c := clearanceFrom(t, rec)
	if c == nil {
		t.Fatal("verify did not set a clearance cookie")
	}
	if !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes: %+v", c)
	}
	if c.MaxAge != int(defaultClearanceTTL/time.Second) {
		t.Errorf("cookie Max-Age = %d, want 30 days", c.MaxAge)
	}

	req := newTurnstileRequest(http.MethodGet, "/articles?page=2", "", nil)
	req.AddCookie(c)
	if rec, reached = serve(t, ts, req); !reached || rec.Code != http.StatusOK {
		t.Errorf("with clearance: got %d (reached=%v), want pass-through", rec.Code, reached)
	}
}

func TestTurnstileRejectsBadTokens(t *testing.T) {
	cases := []struct {
		name, hostname, action, token string
		wantCalls                     int32
	}{
		{"rejected by cloudflare", testHost, turnstileAction, "bad", 1},
		{"wrong hostname", "attacker.example", turnstileAction, "good", 1},
		{"wrong action", testHost, "login", "good", 1},
		{"empty token", testHost, turnstileAction, "", 0},
		{"oversized token", testHost, turnstileAction, strings.Repeat("a", maxTurnstileToken+1), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := fakeSiteverify(t, tc.hostname, tc.action)
			ts := newTestTurnstile(t, srv.URL, false)
			rec, reached := serve(t, ts, newTurnstileRequest(http.MethodPost, defaultVerifyPath, "", url.Values{
				turnstileTokenField: {tc.token},
			}))
			if reached || rec.Code != http.StatusForbidden {
				t.Fatalf("got %d (reached=%v), want 403", rec.Code, reached)
			}
			if clearanceFrom(t, rec) != nil {
				t.Error("a failed verification must not set a cookie")
			}
			if !strings.HasPrefix(rec.Header().Get("X-Block-Id"), "ts-") {
				t.Errorf("X-Block-Id = %q, want a ts- prefix", rec.Header().Get("X-Block-Id"))
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("siteverify called %d times, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestTurnstileTokenReplayRejected(t *testing.T) {
	srv, _ := fakeSiteverify(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, srv.URL, false)
	form := url.Values{turnstileTokenField: {"good"}}

	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, defaultVerifyPath, "", form)); rec.Code != http.StatusSeeOther {
		t.Fatalf("first redemption: got %d, want 303", rec.Code)
	}
	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, defaultVerifyPath, "", form)); rec.Code != http.StatusForbidden {
		t.Errorf("replayed token: got %d, want 403", rec.Code)
	}
}

func TestTurnstileSiteverifyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	ts := newTestTurnstile(t, srv.URL, false)

	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodPost, defaultVerifyPath, "", url.Values{turnstileTokenField: {"good"}}))
	if reached || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d (reached=%v), want 503", rec.Code, reached)
	}
	if clearanceFrom(t, rec) != nil {
		t.Error("no cookie may be issued when siteverify is unreachable")
	}
}

func TestTurnstileClearanceValidation(t *testing.T) {
	ts := newTestTurnstile(t, "http://unused.invalid", false)
	now := time.Unix(1_800_000_000, 0)
	ts.now = func() time.Time { return now }
	req := newTurnstileRequest(http.MethodGet, "/", "", nil)

	fresh := ts.mintClearance(now, req)
	if !ts.validClearance(fresh, req) {
		t.Fatal("freshly minted clearance rejected")
	}

	almost := ts.mintClearance(now.Add(-defaultClearanceTTL+time.Minute), req)
	if !ts.validClearance(almost, req) {
		t.Error("clearance inside its 30 days rejected")
	}
	expired := ts.mintClearance(now.Add(-defaultClearanceTTL-time.Second), req)
	if ts.validClearance(expired, req) {
		t.Error("clearance older than 30 days accepted")
	}
	future := ts.mintClearance(now.Add(time.Hour), req)
	if ts.validClearance(future, req) {
		t.Error("clearance issued in the future accepted")
	}

	// Moving the issue time forward without re-signing must not work.
	parts := strings.Split(expired, ".")
	forged := parts[0] + "." + strings.Split(fresh, ".")[1] + "." + parts[2]
	if ts.validClearance(forged, req) {
		t.Error("clearance with an edited issue time accepted")
	}
	for _, junk := range []string{"", "1", "1.2", "2." + fresh[2:], fresh + "x", "1.abc." + parts[2]} {
		if ts.validClearance(junk, req) {
			t.Errorf("junk clearance %q accepted", junk)
		}
	}

	other := newTurnstileRequest(http.MethodGet, "/", "", nil)
	other.Host = "other.example.com:443"
	if ts.validClearance(fresh, other) {
		t.Error("clearance for one hostname accepted on another")
	}
	withPort := newTurnstileRequest(http.MethodGet, "/", "", nil)
	withPort.Host = "EXAMPLE.com:8443"
	if !ts.validClearance(fresh, withPort) {
		t.Error("clearance rejected because of the port or case in Host")
	}

	differentKey := &Turnstile{SiteKey: testSiteKey, SecretKey: "another-secret"}
	if err := differentKey.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if differentKey.validClearance(fresh, req) {
		t.Error("clearance accepted under a different secret")
	}
}

func TestTurnstileShorterTTLTakesEffectImmediately(t *testing.T) {
	ts := newTestTurnstile(t, "http://unused.invalid", false)
	req := newTurnstileRequest(http.MethodGet, "/", "", nil)
	week := ts.mintClearance(time.Now().Add(-7*24*time.Hour), req)
	ts.ttl = 24 * time.Hour
	if ts.validClearance(week, req) {
		t.Error("a week-old clearance survived lowering the TTL to a day")
	}
}

func TestTurnstileFingerprintBinding(t *testing.T) {
	srv, _ := fakeSiteverify(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, srv.URL, true)

	rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, defaultVerifyPath, testFP, url.Values{turnstileTokenField: {"good"}}))
	c := clearanceFrom(t, rec)
	if c == nil {
		t.Fatalf("no cookie issued (status %d)", rec.Code)
	}

	same := newTurnstileRequest(http.MethodGet, "/", testFP, nil)
	same.AddCookie(c)
	if _, reached := serve(t, ts, same); !reached {
		t.Error("bound clearance rejected for the client it was issued to")
	}

	for _, fp := range []string{"t13d1311h2_e8f1e7e78f70_d339722ba4af", ""} {
		replay := newTurnstileRequest(http.MethodGet, "/", fp, nil)
		replay.AddCookie(c)
		if rec, reached := serve(t, ts, replay); reached || rec.Code != http.StatusForbidden {
			t.Errorf("bound clearance accepted from fingerprint %q", fp)
		}
	}

	// Without binding, the fingerprint is not part of the clearance.
	unbound := newTestTurnstile(t, srv.URL, false)
	req := newTurnstileRequest(http.MethodGet, "/", testFP, nil)
	v := unbound.mintClearance(time.Now(), req)
	if !unbound.validClearance(v, newTurnstileRequest(http.MethodGet, "/", "q13d0312h3_55b375c5d22e_cd8dafe46ac5", nil)) {
		t.Error("unbound clearance depended on the fingerprint")
	}
}

func TestTurnstileOnlyPostIsVerify(t *testing.T) {
	ts := newTestTurnstile(t, "http://unused.invalid", false)
	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodGet, defaultVerifyPath, "", nil))
	if reached || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "cf-turnstile") {
		t.Errorf("GET on verify path without clearance: got %d, want the challenge page", rec.Code)
	}
}

func TestSafeReturnPath(t *testing.T) {
	cases := map[string]string{
		"/":                     "/",
		"/a/b?c=d#e":            "/a/b?c=d#e",
		"":                      "/",
		"https://evil.example/": "/",
		"//evil.example/":       "/",
		"/\\evil.example/":      "/",
		"evil.example":          "/",
		"/ok\r\nSet-Cookie: x":  "/",
		"javascript:alert(1)":   "/",
	}
	for in, want := range cases {
		if got := safeReturnPath(in); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTurnstileCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`turnstile {
		site_key         sk
		secret_key       sec
		clearance_ttl    7d
		cookie_name      cl
		verify_path      /verify
		bind_fingerprint
	}`)
	var ts Turnstile
	if err := ts.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if ts.SiteKey != "sk" || ts.SecretKey != "sec" || ts.CookieName != "cl" || ts.VerifyPath != "/verify" {
		t.Errorf("parsed %+v", ts)
	}
	if time.Duration(ts.ClearanceTTL) != 7*24*time.Hour {
		t.Errorf("clearance_ttl = %v, want 7 days", time.Duration(ts.ClearanceTTL))
	}
	if ts.BindFingerprintVar != "ja4" {
		t.Errorf("bare bind_fingerprint should bind to ja4, got %q", ts.BindFingerprintVar)
	}

	d = caddyfile.NewTestDispenser(`turnstile {
		bind_fingerprint fp
	}`)
	ts = Turnstile{}
	if err := ts.UnmarshalCaddyfile(d); err != nil || ts.BindFingerprintVar != "fp" {
		t.Errorf("bind_fingerprint fp: %q, %v", ts.BindFingerprintVar, err)
	}

	for _, bad := range []string{
		"turnstile {\nnope x\n}",
		"turnstile {\nsite_key\n}",
		"turnstile {\nsite_key a b\n}",
		"turnstile {\nclearance_ttl soon\n}",
		`turnstile inline`,
	} {
		var ts Turnstile
		if err := ts.UnmarshalCaddyfile(caddyfile.NewTestDispenser(bad)); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestTurnstileProvisionErrors(t *testing.T) {
	for name, ts := range map[string]*Turnstile{
		"no site key":      {SecretKey: "s"},
		"no secret key":    {SiteKey: "s"},
		"short clearance":  {SiteKey: "s", SecretKey: "s", ClearanceKey: "short"},
		"relative path":    {SiteKey: "s", SecretKey: "s", VerifyPath: "verify"},
		"negative ttl":     {SiteKey: "s", SecretKey: "s", ClearanceTTL: caddy.Duration(-time.Hour)},
		"unset env secret": {SiteKey: "s", SecretKey: "{env.BOT_POLICY_TEST_UNSET_VAR}"},
	} {
		if err := ts.Provision(caddy.Context{}); err == nil {
			t.Errorf("%s: expected Provision to fail", name)
		}
	}
}

func TestTurnstileProvisionExpandsEnv(t *testing.T) {
	t.Setenv("BOT_POLICY_TEST_SECRET", testSecretKey)
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: "{env.BOT_POLICY_TEST_SECRET}"}
	if err := ts.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if ts.SecretKey != testSecretKey {
		t.Errorf("secret_key not expanded: %q", ts.SecretKey)
	}
}
