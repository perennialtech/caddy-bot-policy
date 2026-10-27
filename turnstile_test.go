package botpolicy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	testFP        = "t13d1517h2_8daaf6152771_b6f405a00624"
	testFPQUIC    = "q13d0312h3_55b375c5d22e_cd8dafe46ac5"
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

func newTestTurnstile(t *testing.T, bind bool) *Turnstile {
	t.Helper()
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey}
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
	ts := newTestTurnstile(t, false)

	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodGet, "/articles?page=2&sort=new", "", nil))
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

	rec, reached = serve(t, ts, newTurnstileRequest(http.MethodPost, "/articles?page=2&sort=new", "", solve("good")))
	if reached || rec.Code != http.StatusSeeOther {
		t.Fatalf("verify: got %d (reached=%v), want 303", rec.Code, reached)
	}
	if loc := rec.Header().Get("Location"); loc != "/articles?page=2&sort=new" {
		t.Errorf("verify redirected to %q, want the original page", loc)
	}
	c := cookieFrom(rec, ts.cookieName("", false))
	if c == nil {
		t.Fatal("verify did not set a clearance cookie")
	}
	if !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie attributes: %+v", c)
	}
	if c.MaxAge != int(defaultClearanceTTL/time.Second) {
		t.Errorf("cookie Max-Age = %d, want 30 days", c.MaxAge)
	}

	req := newTurnstileRequest(http.MethodGet, "/articles?page=2&sort=new", "", nil)
	req.AddCookie(c)
	if rec, reached = serve(t, ts, req); !reached || rec.Code != http.StatusOK {
		t.Errorf("with clearance: got %d (reached=%v), want pass-through", rec.Code, reached)
	}

	// A cleared POST must reach the app untouched, marker or not.
	req = newTurnstileRequest(http.MethodPost, "/form", "", solve("whatever"))
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
	ts := newTestTurnstile(t, false)

	rewritten := func(method string, body url.Values) *http.Request {
		req := newTurnstileRequest(method, "/articles/hello?x=1", "", body)
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
	ts := newTestTurnstile(t, false)
	rec := httptest.NewRecorder()
	// A site-wide CSP set by an earlier header directive.
	rec.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
	req := newTurnstileRequest(http.MethodGet, "/", "", nil)
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
	ts := newTestTurnstile(t, false)

	for name, req := range map[string]*http.Request{
		"app form":   newTurnstileRequest(http.MethodPost, "/login", "", url.Values{"user": {"a"}, turnstileTokenField: {"good"}}),
		"json":       newTurnstileRequest(http.MethodPost, "/api", "", nil),
		"get marker": newTurnstileRequest(http.MethodGet, "/?"+turnstileMarkerField+"=1&"+turnstileTokenField+"=good", "", nil),
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
			ts := newTestTurnstile(t, false)
			rec, reached := serve(t, ts, newTurnstileRequest(http.MethodPost, "/page?a=b", "", solve(tc.token)))
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
	ts := newTestTurnstile(t, false)

	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", "", solve("good"))); rec.Code != http.StatusSeeOther {
		t.Fatalf("first redemption: got %d, want 303", rec.Code)
	}
	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", "", solve("good"))); rec.Code != http.StatusForbidden {
		t.Errorf("replayed token: got %d, want 403", rec.Code)
	}
}

func TestTurnstileTestingKeys(t *testing.T) {
	// Cloudflare's testing secrets report example.com and no action,
	// whatever site the widget is on.
	f := &fakeSiteverify{hostname: "example.com", testingKey: true}
	useSiteverify(t, f)
	ts := newTestTurnstile(t, false)

	req := newTurnstileRequest(http.MethodPost, "/", "", solve("good"))
	req.Host = "localhost:8443"
	if rec, _ := serve(t, ts, req); rec.Code != http.StatusSeeOther {
		t.Errorf("testing-key result: got %d, want 303", rec.Code)
	}

	// Without the testing-key marker, the same missing action is a reject.
	f2 := &fakeSiteverify{hostname: "example.com"}
	useSiteverify(t, f2)
	req = newTurnstileRequest(http.MethodPost, "/", "", solve("good"))
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
	ts := newTestTurnstile(t, false)

	rec, reached := serve(t, ts, newTurnstileRequest(http.MethodPost, "/x", "", solve("good")))
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
			_ = ts.ServeHTTP(rec, newTurnstileRequest(http.MethodPost, "/", "", solve("bad")), nil)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", "", solve("good")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("third concurrent verification: got %d, want 503", rec.Code)
	}
	if got := f.calls.Load(); got != 2 {
		t.Errorf("siteverify called %d times, want 2 (the third must not go out)", got)
	}
	close(f.hold)
	wg.Wait()

	if rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", "", solve("good"))); rec.Code != http.StatusSeeOther {
		t.Errorf("after the slots freed up: got %d, want 303", rec.Code)
	}
}

func TestTurnstileClearanceValidation(t *testing.T) {
	ts := newTestTurnstile(t, false)
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
	ts := newTestTurnstile(t, false)
	req := newTurnstileRequest(http.MethodGet, "/", "", nil)
	week := ts.mintClearance(time.Now().Add(-7*24*time.Hour), req)
	ts.ttl = 24 * time.Hour
	if ts.validClearance(week, req) {
		t.Error("a week-old clearance survived lowering the TTL to a day")
	}
}

// clearOnce solves the challenge for fp and returns the cookie issued.
func clearOnce(t *testing.T, ts *Turnstile, fp string) *http.Cookie {
	t.Helper()
	rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", fp, solve("good")))
	if rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("clearing %q: got %d with %d cookies", fp, rec.Code, len(rec.Result().Cookies()))
	}
	return rec.Result().Cookies()[0]
}

func passes(t *testing.T, ts *Turnstile, fp string, cookies ...*http.Cookie) bool {
	t.Helper()
	req := newTurnstileRequest(http.MethodGet, "/", fp, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	_, reached := serve(t, ts, req)
	return reached
}

func TestTurnstileFingerprintBinding(t *testing.T) {
	newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, true)

	c := clearOnce(t, ts, testFP)
	if c.Name != ts.cookieName(testFP, true) {
		t.Errorf("bound cookie over TCP is named %q, want %q", c.Name, ts.cookieName(testFP, true))
	}
	if !passes(t, ts, testFP, c) {
		t.Error("bound clearance rejected for the client it was issued to")
	}
	if passes(t, ts, "t13d1311h2_e8f1e7e78f70_d339722ba4af", c) {
		t.Error("bound clearance accepted from a different fingerprint")
	}
	if passes(t, ts, "", c) {
		t.Error("bound clearance accepted from a request without a fingerprint")
	}

	// An unbound clearance for the same host and key, put under the bound
	// cookie's name, must not be accepted: the mode is part of the MAC.
	unbound := newTestTurnstile(t, false)
	forged := &http.Cookie{Name: c.Name, Value: unbound.mintClearance(time.Now(), newTurnstileRequest(http.MethodGet, "/", "", nil))}
	if passes(t, ts, testFP, forged) {
		t.Error("unbound clearance accepted by a binding handler")
	}

	// Without binding, the fingerprint is not part of the clearance.
	v := unbound.mintClearance(time.Now(), newTurnstileRequest(http.MethodGet, "/", testFP, nil))
	if !unbound.validClearance(v, newTurnstileRequest(http.MethodGet, "/", testFPQUIC, nil)) {
		t.Error("unbound clearance depended on the fingerprint")
	}
}

// TestTurnstileBindingSurvivesProtocolSwitching is the h2 -> h3 -> h2 case: a
// browser that has passed once over each transport must not be challenged
// again when it moves between them.
func TestTurnstileBindingSurvivesProtocolSwitching(t *testing.T) {
	f := &fakeSiteverify{hostname: testHost, action: turnstileAction}
	useSiteverify(t, f)
	ts := newTestTurnstile(t, true)

	tcp := clearOnce(t, ts, testFP)
	if passes(t, ts, testFPQUIC, tcp) {
		t.Fatal("TCP clearance accepted over QUIC")
	}
	f.redeemed.Store(false) // a second, fresh token
	quic := clearOnce(t, ts, testFPQUIC)
	if quic.Name == tcp.Name {
		t.Fatalf("both transports share cookie %q, so each switch would overwrite the other", tcp.Name)
	}

	// The browser now holds both cookies and keeps sending both.
	for i, fp := range []string{testFP, testFPQUIC, testFP, testFPQUIC} {
		if !passes(t, ts, fp, tcp, quic) {
			t.Errorf("switch %d (%s): challenged again", i, fp[:1])
		}
	}
}

func TestTurnstileBindingRequiresFingerprint(t *testing.T) {
	f := newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, true)

	rec, _ := serve(t, ts, newTurnstileRequest(http.MethodPost, "/", "", solve("good")))
	if rec.Code != http.StatusForbidden || anyCookie(rec) {
		t.Errorf("binding with no fingerprint: got %d (cookie=%v), want 403 and no cookie", rec.Code, anyCookie(rec))
	}
	if f.calls.Load() != 0 {
		t.Error("siteverify was called although no clearance could be issued")
	}
	// The token was not spent, so the visitor is not worse off once the
	// fingerprint shows up (e.g. after the operator fixes the config).
	if f.redeemed.Load() {
		t.Error("token was redeemed")
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
		bind_fingerprint
		max_pending_verifications 8
	}`)
	var ts Turnstile
	if err := ts.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if ts.SiteKey != "sk" || ts.SecretKey != "sec" || ts.CookieName != "cl" || ts.MaxPendingVerifications != 8 {
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
		"turnstile {\nverify_path /x\n}",
		"turnstile {\nmax_pending_verifications 0\n}",
		"turnstile {\nmax_pending_verifications lots\n}",
		"turnstile {\nbind_fingerprint a b\n}",
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
		"bad var name":          ok(func(ts *Turnstile) { ts.BindFingerprintVar = "ja4 }" }),
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

// Different TCP ClientHellos (such as h2 versus h1-only) must not replace
// each other's clearance in a browser's cookie jar.
func TestTurnstileBindingSurvivesTCPProfileSwitching(t *testing.T) {
	f := &fakeSiteverify{hostname: testHost, action: turnstileAction}
	useSiteverify(t, f)
	ts := newTestTurnstile(t, true)
	const otherTCP = "t13d1311h1_e8f1e7e78f70_d339722ba4af"

	a := clearOnce(t, ts, testFP)
	f.redeemed.Store(false)
	b := clearOnce(t, ts, otherTCP)
	if a.Name == b.Name {
		t.Fatalf("different TCP JA4s share cookie name %q", a.Name)
	}
	for i, fp := range []string{testFP, otherTCP, testFP, otherTCP} {
		if !passes(t, ts, fp, a, b) {
			t.Errorf("profile switch %d: clearance lost", i)
		}
	}
}

// Two independent path-scoped policies on the same host must not overwrite
// each other's cookies, with or without JA4 binding.
func TestTurnstileCookieNamesIsolateConfigurations(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(fmt.Sprintf("bound=%t", bound), func(t *testing.T) {
			f := &fakeSiteverify{hostname: testHost, action: turnstileAction}
			useSiteverify(t, f)
			a := newTestTurnstile(t, bound)
			b := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey, ClearanceKey: strings.Repeat("b", 32)}
			if bound {
				b.BindFingerprintVar = "ja4"
			}
			if err := b.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			fp := ""
			if bound {
				fp = testFP
			}
			ca := clearOnce(t, a, fp)
			f.redeemed.Store(false)
			cb := clearOnce(t, b, fp)
			if ca.Name == cb.Name {
				t.Fatalf("different signing keys share cookie %q", ca.Name)
			}
			for i, ts := range []*Turnstile{a, b, a, b} {
				if !passes(t, ts, fp, ca, cb) {
					t.Errorf("policy switch %d: clearance lost", i)
				}
			}
			// Identical instances must agree on cookie names and MACs.
			clone := newTestTurnstile(t, bound)
			if clone.cookieName(fp, bound) != ca.Name || !passes(t, clone, fp, ca, cb) {
				t.Error("clearance was not stable across identical instances")
			}
			differentWidget := newTestTurnstile(t, bound)
			differentWidget.SiteKey = "another-widget-key"
			if differentWidget.cookieName(fp, bound) == ca.Name {
				t.Error("different site keys share a cookie slot")
			}
			differentSecret := &Turnstile{SiteKey: testSiteKey, SecretKey: "another-secret"}
			if bound {
				differentSecret.BindFingerprintVar = "ja4"
			}
			if err := differentSecret.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			if differentSecret.cookieName(fp, bound) == ca.Name {
				t.Error("different default-derived signing keys share a cookie slot")
			}
		})
	}
}

// A migrated HTTP/3 connection retains its TLS handshake but changes UDP
// source address. The packet sniffer cannot link it to the original Initial.
// Verify that Turnstile fails closed rather than granting an unbound cookie.
func TestTurnstileQUICMigrationFailsClosed(t *testing.T) {
	f := newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, true)
	h := &Handler{VarName: "ja4"}
	const oldAddr = "192.0.2.11:41000"
	const newAddr = "192.0.2.12:41001"
	quicConns.set(normalizeAddr(oldAddr), testFPQUIC)
	defer quicConns.delete(normalizeAddr(oldAddr))

	request := func(method, addr string, body url.Values, cookie *http.Cookie) *http.Request {
		r := newTurnstileRequest(method, "/members", "", body)
		r.Proto, r.ProtoMajor, r.ProtoMinor, r.RemoteAddr = "HTTP/3.0", 3, 0, addr
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return r
	}
	serveThroughJA4 := func(r *http.Request) (*httptest.ResponseRecorder, bool) {
		t.Helper()
		var reached bool
		w := httptest.NewRecorder()
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			reached = true
			w.WriteHeader(http.StatusOK)
			return nil
		})
		if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			return ts.ServeHTTP(w, r, next)
		})); err != nil {
			t.Fatal(err)
		}
		return w, reached
	}

	// A valid bound cookie is accepted on the original connection address.
	issued := ts.mintClearance(time.Now(), newTurnstileRequest(http.MethodGet, "/members", testFPQUIC, nil))
	cookie := &http.Cookie{Name: ts.cookieName(testFPQUIC, true), Value: issued}
	if rec, reached := serveThroughJA4(request(http.MethodGet, oldAddr, nil, cookie)); rec.Code != http.StatusOK || !reached {
		t.Fatalf("initial address: %d, reached=%t", rec.Code, reached)
	}
	if rec, reached := serveThroughJA4(request(http.MethodGet, newAddr, nil, cookie)); rec.Code != http.StatusForbidden || reached {
		t.Fatalf("migrated address: %d, reached=%t; expected a challenge", rec.Code, reached)
	}
	if rec, reached := serveThroughJA4(request(http.MethodPost, newAddr, solve("good"), cookie)); rec.Code != http.StatusForbidden || reached || anyCookie(rec) {
		t.Fatalf("migrated verification: %d, reached=%t, cookies=%v", rec.Code, reached, rec.Result().Cookies())
	}
	if got := f.calls.Load(); got != 0 {
		t.Errorf("siteverify was called %d times on an unbindable connection", got)
	}
}
