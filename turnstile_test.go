package turnstile

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	testSiteKey   = "1x00000000000000000000AA"
	testSecretKey = "test-secret-key"
	testHost      = "example.com"
)

// fakeSiteverify stands in for Cloudflare. It accepts exactly one token,
// "good", once, and reports the given hostname and action for it. With
// testingKey it answers the way Cloudflare does for its public testing
// secrets: no action, and metadata.result_with_testing_key set.
type fakeSiteverify struct {
	hostname, action string
	testingKey       bool
	calls            atomic.Int32
	redeemed         atomic.Bool
	hold             chan struct{} // if set, each call waits on it
}

func (f *fakeSiteverify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if f.hold != nil {
		<-f.hold
	}
	_ = r.ParseForm()
	res := map[string]any{"hostname": f.hostname, "error-codes": []string{}}
	if f.testingKey {
		res["metadata"] = map[string]any{"result_with_testing_key": true}
	} else if f.action != "" {
		res["action"] = f.action
	}
	switch {
	case r.PostForm.Get("secret") != testSecretKey:
		res["error-codes"] = []string{"invalid-input-secret"}
	case r.PostForm.Get("response") != "good":
		res["error-codes"] = []string{"invalid-input-response"}
	case f.redeemed.Swap(true):
		res["error-codes"] = []string{"timeout-or-duplicate"}
	default:
		res["success"] = true
	}
	_ = json.NewEncoder(w).Encode(res)
}

// useSiteverify points the handler's siteverify calls at h for one test.
func useSiteverify(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	old := siteverifyURL
	siteverifyURL = srv.URL
	t.Cleanup(func() {
		siteverifyURL = old
		srv.Close()
	})
	return srv
}

func newFake(t *testing.T, hostname, action string) *fakeSiteverify {
	t.Helper()
	f := &fakeSiteverify{hostname: hostname, action: action}
	useSiteverify(t, f)
	return f
}

func newTestTurnstile(t *testing.T) *Turnstile {
	t.Helper()
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey}
	if err := ts.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return ts
}

func newTurnstileRequest(method, target string, body url.Values) *http.Request {
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
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
	return req.WithContext(ctx)
}

// solve is the form the challenge page posts.
func solve(token string) url.Values {
	return url.Values{turnstileMarkerField: {"1"}, turnstileTokenField: {token}}
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

func cookieFrom(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func anyCookie(rec *httptest.ResponseRecorder) bool { return len(rec.Result().Cookies()) > 0 }

var noncePattern = regexp.MustCompile(`'nonce-([A-Za-z0-9_-]+)'`)

// TestTurnstileFullFlow walks a visitor through the whole thing: challenged,
// solves, gets a cookie, comes back with it and is let through.
func TestTurnstileFullFlow(t *testing.T) {
	newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t)

	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodGet, "/articles?page=2&sort=new", nil))
	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("no cookie: got %d (reached=%v), want a 403 challenge", rec.Code, reached)
	}
	page := rec.Body.String()
	for _, want := range []string{
		testSiteKey, turnstileAction, turnstileMarkerField,
		`action="/articles?page=2&amp;sort=new"`,
		"challenges.cloudflare.com/turnstile/v0/api.js",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("challenge page is missing %q", want)
		}
	}
	if strings.Contains(page, "<button") {
		t.Error("challenge page must not offer a submit button before a token exists")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("challenge page must not be cacheable")
	}

	rec, reached = serve(t, ts, newTurnstileRequest(http.MethodPost, "/articles?page=2&sort=new", solve("good")))
	if reached || rec.Code != http.StatusSeeOther {
		t.Fatalf("verify: got %d (reached=%v), want 303", rec.Code, reached)
	}
	if loc := rec.Header().Get("Location"); loc != "/articles?page=2&sort=new" {
		t.Errorf("verify redirected to %q, want the original page", loc)
	}
	c := cookieFrom(rec, ts.cookieName())
	if c == nil {
		t.Fatal("verify did not set a clearance cookie")
	}
	if !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes: %+v", c)
	}
	if c.MaxAge != int(defaultClearanceTTL/time.Second) {
		t.Errorf("cookie Max-Age = %d, want 30 days", c.MaxAge)
	}

	req := newTurnstileRequest(http.MethodGet, "/articles?page=2&sort=new", nil)
	req.AddCookie(c)
	if rec, reached = serve(t, ts, req); !reached || rec.Code != http.StatusOK {
		t.Errorf("with clearance: got %d (reached=%v), want pass-through", rec.Code, reached)
	}

	// A cleared POST must reach the app untouched, marker or not.
	req = newTurnstileRequest(http.MethodPost, "/form", solve("whatever"))
	req.AddCookie(c)
	if _, reached = serve(t, ts, req); !reached {
		t.Error("a cleared POST was intercepted")
	}
}

// TestTurnstileUsesOriginalURI checks that a URL rewritten before the handler
// runs (rewrite, try_files, handle_path) does not leak into the form action
// or the redirect.
func TestTurnstileUsesOriginalURI(t *testing.T) {
	newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t)

	rewritten := func(method string, body url.Values) *http.Request {
		req := newTurnstileRequest(method, "/articles/hello?x=1", body)
		orig := *req
		orig.URL = &url.URL{Path: "/articles/hello", RawQuery: "x=1"}
		req = req.WithContext(context.WithValue(req.Context(), caddyhttp.OriginalRequestCtxKey, orig))
		req.URL.Path, req.URL.RawQuery = "/index.html", ""
		return req
	}

	rec, _ := serve(t, ts, rewritten(http.MethodGet, nil))
	if !strings.Contains(rec.Body.String(), `action="/articles/hello?x=1"`) {
		t.Errorf("form action does not use the original URL:\n%s", rec.Body.String())
	}
	rec, _ = serve(t, ts, rewritten(http.MethodPost, solve("good")))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/articles/hello?x=1" {
		t.Errorf("verify: got %d to %q, want 303 to the original URL", rec.Code, rec.Header().Get("Location"))
	}
}

func TestTurnstileChallengeCSP(t *testing.T) {
	ts := newTestTurnstile(t)
	rec := httptest.NewRecorder()
	// A site-wide CSP set by an earlier header directive.
	rec.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
	req := newTurnstileRequest(http.MethodGet, "/", nil)
	if err := ts.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })); err != nil {
		t.Fatal(err)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"'strict-dynamic'", "frame-src https://challenges.cloudflare.com", "form-action 'self'", "object-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q is missing %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP %q: site policy was not replaced, or unsafe-inline used", csp)
	}
	m := noncePattern.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no nonce in CSP %q", csp)
	}
	body := rec.Body.String()
	if n := strings.Count(body, `<script nonce="`+m[1]+`"`); n != 2 {
		t.Errorf("%d scripts carry the CSP nonce, want 2 (api.js and the callback)", n)
	}
	if strings.Count(body, "<script") != 2 {
		t.Error("page has a script without the nonce")
	}

	rec2 := httptest.NewRecorder()
	_ = ts.ServeHTTP(rec2, req, nil)
	if noncePattern.FindStringSubmatch(rec2.Header().Get("Content-Security-Policy"))[1] == m[1] {
		t.Error("nonce reused between responses")
	}
}

func TestTurnstileUnrelatedPostIsChallenged(t *testing.T) {
	f := newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t)

	for name, req := range map[string]*http.Request{
		"app form":   newTurnstileRequest(http.MethodPost, "/login", url.Values{"user": {"a"}, turnstileTokenField: {"good"}}),
		"json":       newTurnstileRequest(http.MethodPost, "/api", nil),
		"get marker": newTurnstileRequest(http.MethodGet, "/?"+turnstileMarkerField+"=1&"+turnstileTokenField+"=good", nil),
	} {
		rec, reached := serve(t, ts, req)
		if reached || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "cf-turnstile") {
			t.Errorf("%s: got %d (reached=%v), want the challenge page", name, rec.Code, reached)
		}
	}
	if f.calls.Load() != 0 {
		t.Errorf("siteverify called %d times for requests that were not challenge submissions", f.calls.Load())
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
		{"no action", testHost, "", "good", 1},
		{"empty token", testHost, turnstileAction, "", 0},
		{"oversized token", testHost, turnstileAction, strings.Repeat("a", maxTurnstileToken+1), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, tc.hostname, tc.action)
			ts := newTestTurnstile(t)
			rec, reached := serve(t, ts, newTurnstileRequest(http.MethodPost, "/page?a=b", solve(tc.token)))
			if reached || rec.Code != http.StatusForbidden {
				t.Fatalf("got %d (reached=%v), want 403", rec.Code, reached)
			}
			if anyCookie(rec) {
				t.Error("a failed verification must not set a cookie")
			}
			id := rec.Header().Get("X-Block-Id")
			if !strings.HasPrefix(id, "ts-") {
				t.Errorf("X-Block-Id = %q, want a ts- prefix", id)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `href="/page?a=b"`) || !strings.Contains(body, id) {
				t.Errorf("failure page needs a retry link to the original URL and the block ID:\n%s", body)
			}
			if got := f.calls.Load(); got != tc.wantCalls {
				t.Errorf("siteverify called %d times, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestTurnstileTokenReplayRejected(t *testing.T) {
	newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t)

	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", solve("good"))); rec.Code != http.StatusSeeOther {
		t.Fatalf("first redemption: got %d, want 303", rec.Code)
	}
	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", solve("good"))); rec.Code != http.StatusForbidden {
		t.Errorf("replayed token: got %d, want 403", rec.Code)
	}
}

func TestTurnstileTestingKeys(t *testing.T) {
	// Cloudflare's testing secrets report example.com and no action,
	// whatever site the widget is on.
	f := &fakeSiteverify{hostname: "example.com", testingKey: true}
	useSiteverify(t, f)
	ts := newTestTurnstile(t)

	req := newTurnstileRequest(http.MethodPost, "/", solve("good"))
	req.Host = "localhost:8443"
	if rec, _ := serve(t, ts, req); rec.Code != http.StatusSeeOther {
		t.Errorf("testing-key result: got %d, want 303", rec.Code)
	}

	// Without the testing-key marker, the same missing action is a reject.
	f2 := &fakeSiteverify{hostname: "example.com"}
	useSiteverify(t, f2)
	req = newTurnstileRequest(http.MethodPost, "/", solve("good"))
	if rec, _ := serve(t, ts, req); rec.Code != http.StatusForbidden {
		t.Errorf("production result without action: got %d, want 403", rec.Code)
	}

	if !isDummySecret("1x0000000000000000000000000000000AA") || !isDummySecret("3x0000000000000000000000000000000AA") {
		t.Error("published testing secrets not recognized")
	}
	if isDummySecret("0x4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") || isDummySecret(testSecretKey) {
		t.Error("ordinary secret recognized as a testing key")
	}
}

func TestTurnstileSiteverifyUnavailable(t *testing.T) {
	useSiteverify(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	ts := newTestTurnstile(t)

	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodPost, "/x", solve("good")))
	if reached || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d (reached=%v), want 503", rec.Code, reached)
	}
	if anyCookie(rec) {
		t.Error("no cookie may be issued when siteverify is unreachable")
	}
	if !strings.Contains(rec.Body.String(), `href="/x"`) || rec.Header().Get("Retry-After") == "" {
		t.Error("503 page needs a retry link and Retry-After")
	}
}

func TestTurnstilePendingVerificationsBounded(t *testing.T) {
	f := &fakeSiteverify{hostname: testHost, action: turnstileAction, hold: make(chan struct{})}
	useSiteverify(t, f)
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey, MaxPendingVerifications: 2}
	if err := ts.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			_ = ts.ServeHTTP(rec, newTurnstileRequest(http.MethodPost, "/", solve("bad")), nil)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", solve("good")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("third concurrent verification: got %d, want 503", rec.Code)
	}
	if got := f.calls.Load(); got != 2 {
		t.Errorf("siteverify called %d times, want 2 (the third must not go out)", got)
	}
	close(f.hold)
	wg.Wait()

	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", solve("good"))); rec.Code != http.StatusSeeOther {
		t.Errorf("after the slots freed up: got %d, want 303", rec.Code)
	}
}

func TestTurnstileClearanceValidation(t *testing.T) {
	ts := newTestTurnstile(t)
	now := time.Unix(1_800_000_000, 0)
	ts.now = func() time.Time { return now }
	req := newTurnstileRequest(http.MethodGet, "/", nil)

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
	for _, junk := range []string{"", "1", "1.2", "1." + strings.TrimPrefix(fresh, "3."), "2." + strings.TrimPrefix(fresh, "3."), "4." + strings.TrimPrefix(fresh, "3."), fresh + "x", "3.abc." + parts[2]} {
		if ts.validClearance(junk, req) {
			t.Errorf("junk clearance %q accepted", junk)
		}
	}

	other := newTurnstileRequest(http.MethodGet, "/", nil)
	other.Host = "other.example.com:443"
	if ts.validClearance(fresh, other) {
		t.Error("clearance for one hostname accepted on another")
	}
	withPort := newTurnstileRequest(http.MethodGet, "/", nil)
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
	ts := newTestTurnstile(t)
	req := newTurnstileRequest(http.MethodGet, "/", nil)
	week := ts.mintClearance(time.Now().Add(-7*24*time.Hour), req)
	ts.ttl = 24 * time.Hour
	if ts.validClearance(week, req) {
		t.Error("a week-old clearance survived lowering the TTL to a day")
	}
}

// Separate protection policies cannot accept or overwrite each other's
// clearances, even if they share a signing key.
func TestTurnstileClearancePolicyIsolation(t *testing.T) {
	const sharedKey = "shared-clearance-signing-key-32-bytes"
	makePolicy := func(site, secret, cookie string) *Turnstile {
		t.Helper()
		ts := &Turnstile{
			SiteKey: site, SecretKey: secret, ClearanceKey: sharedKey,
			CookieName: cookie,
		}
		if err := ts.Provision(caddy.Context{}); err != nil {
			t.Fatal(err)
		}
		return ts
	}
	a := makePolicy("widget-a", "secret-a", "")
	b := makePolicy("widget-b", "secret-b", "")
	renamed := makePolicy("widget-a", "secret-a", "other_route")
	rotated := makePolicy("widget-a", "rotated-secret", "")
	req := newTurnstileRequest(http.MethodGet, "/private", nil)
	value := a.mintClearance(time.Now(), req)
	if !a.validClearance(value, req) || !rotated.validClearance(value, req) {
		t.Fatal("clearance was not reusable by the same policy after secret rotation")
	}
	for _, tc := range []struct {
		name   string
		policy *Turnstile
	}{
		{"different widget", b},
		{"different cookie prefix", renamed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.policy.cookieName() == a.cookieName() {
				t.Fatal("different protection policies share cookie names")
			}
			if tc.policy.validClearance(value, req) {
				t.Fatal("clearance accepted by another policy")
			}
			request := newTurnstileRequest(http.MethodGet, "/private", nil)
			request.AddCookie(&http.Cookie{Name: tc.policy.cookieName(), Value: value})
			if tc.policy.cleared(request) {
				t.Fatal("transplanted cookie bypassed another policy")
			}
		})
	}
	clone := makePolicy("widget-a", "secret-a", "")
	if clone.cookieName() != a.cookieName() || !clone.validClearance(value, req) {
		t.Fatal("identical policies have unstable clearances")
	}
}

func TestSafeReturnPath(t *testing.T) {
	cases := map[string]string{
		"/":                     "/",
		"/a/b?c=d":              "/a/b?c=d",
		"":                      "/",
		"*":                     "/",
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
		max_pending_verifications 8
		allow_insecure_cookie
	}`)
	var ts Turnstile
	if err := ts.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if ts.SiteKey != "sk" || ts.SecretKey != "sec" || ts.CookieName != "cl" || ts.MaxPendingVerifications != 8 || !ts.AllowInsecureCookie {
		t.Errorf("parsed %+v", ts)
	}
	if time.Duration(ts.ClearanceTTL) != 7*24*time.Hour {
		t.Errorf("clearance_ttl = %v, want 7 days", time.Duration(ts.ClearanceTTL))
	}

	for _, bad := range []string{
		"turnstile {\nnope x\n}",
		"turnstile {\nsite_key\n}",
		"turnstile {\nsite_key a b\n}",
		"turnstile {\nclearance_ttl soon\n}",
		"turnstile {\nverify_path /x\n}",
		"turnstile {\nmax_pending_verifications 0\n}",
		"turnstile {\nmax_pending_verifications lots\n}",
		"turnstile {\nallow_insecure_cookie yes\n}",
		`turnstile inline`,
	} {
		var ts Turnstile
		if err := ts.UnmarshalCaddyfile(caddyfile.NewTestDispenser(bad)); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestTurnstileProvisionErrors(t *testing.T) {
	ok := func(mod func(*Turnstile)) *Turnstile {
		ts := &Turnstile{SiteKey: "s", SecretKey: "s"}
		mod(ts)
		return ts
	}
	for name, ts := range map[string]*Turnstile{
		"no site key":           {SecretKey: "s"},
		"no secret key":         {SiteKey: "s"},
		"unset env secret":      {SiteKey: "s", SecretKey: "{env.BOT_POLICY_TEST_UNSET_VAR}"},
		"short clearance key":   ok(func(ts *Turnstile) { ts.ClearanceKey = "short" }),
		"negative ttl":          ok(func(ts *Turnstile) { ts.ClearanceTTL = caddy.Duration(-time.Hour) }),
		"ttl under a minute":    ok(func(ts *Turnstile) { ts.ClearanceTTL = caddy.Duration(30 * time.Second) }),
		"ttl over 400 days":     ok(func(ts *Turnstile) { ts.ClearanceTTL = caddy.Duration(401 * 24 * time.Hour) }),
		"cookie name space":     ok(func(ts *Turnstile) { ts.CookieName = "bad name" }),
		"cookie name semicolon": ok(func(ts *Turnstile) { ts.CookieName = "a;b" }),
		"cookie name equals":    ok(func(ts *Turnstile) { ts.CookieName = "a=b" }),
		"negative pending":      ok(func(ts *Turnstile) { ts.MaxPendingVerifications = -1 }),
	} {
		if err := ts.Provision(caddy.Context{}); err == nil {
			t.Errorf("%s: expected Provision to fail", name)
		}
	}
	if err := ok(func(ts *Turnstile) { ts.ClearanceTTL = caddy.Duration(400 * 24 * time.Hour) }).Provision(caddy.Context{}); err != nil {
		t.Errorf("400-day TTL should be allowed: %v", err)
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

func TestTurnstileSecureCookiesBehindTLSProxy(t *testing.T) {
	f := newFake(t, testHost, turnstileAction)
	for _, tc := range []struct {
		name, forwarded string
		insecure        bool
		wantSecure      bool
	}{
		{"tls terminated upstream", "https", false, true},
		{"direct HTTP defaults secure", "", false, true},
		{"untrusted forwarded HTTP does not downgrade", "http", false, true},
		{"explicit HTTP-only development mode", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.redeemed.Store(false)
			ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey, AllowInsecureCookie: tc.insecure}
			if err := ts.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			r := newTurnstileRequest(http.MethodPost, "/", solve("good"))
			r.TLS = nil // Caddy sees only the plain HTTP hop from a TLS proxy.
			if tc.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}
			rec, _ := serve(t, ts, r)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("verify status = %d, want 303", rec.Code)
			}
			c := cookieFrom(rec, ts.cookieName())
			if c == nil || c.Secure != tc.wantSecure || !c.HttpOnly {
				t.Errorf("cookie = %+v; want Secure=%t and HttpOnly", c, tc.wantSecure)
			}
		})
	}
}
