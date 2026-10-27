package botpolicy

// Integration tests: these load real Caddyfiles through Caddy's own adapter
// and route real HTTP requests through a running server, so they catch what
// calling Turnstile.ServeHTTP directly cannot — directive ordering, matcher
// scoping, and URL rewrites that happen before the handler.

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

const integrationTurnstile = `turnstile {
		site_key   ` + testSiteKey + `
		secret_key ` + testSecretKey + `
	}`

// startCaddy runs site (the body of a site block) on a free local port and
// returns the base URL. Every %TURNSTILE% in site is replaced with a
// configured turnstile directive.
func startCaddy(t *testing.T, site string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	site = strings.ReplaceAll(site, "%TURNSTILE%", integrationTurnstile)
	cfg := "{\n\tadmin off\n\tauto_https off\n\tpersist_config off\n}\n\nhttp://" + addr + " {\n" + site + "\n}\n"
	adapted, _, err := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}.Adapt([]byte(cfg), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v\n%s", err, cfg)
	}
	if err := caddy.Load(adapted, true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	return "http://" + addr
}

// visitor is a browser without JavaScript: it keeps cookies, does not follow
// redirects, and submits the challenge form by hand.
type visitor struct {
	t       *testing.T
	base    string
	client  *http.Client
	cookies []*http.Cookie
}

func newVisitor(t *testing.T, base string) *visitor {
	return &visitor{t: t, base: base, client: &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (v *visitor) do(req *http.Request) (*http.Response, string) {
	v.t.Helper()
	for _, c := range v.cookies {
		req.AddCookie(c)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		v.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	v.cookies = append(v.cookies, resp.Cookies()...)
	return resp, string(body)
}

func (v *visitor) get(path string) (*http.Response, string) {
	v.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, v.base+path, nil)
	return v.do(req)
}

func (v *visitor) post(path string, form url.Values) (*http.Response, string) {
	v.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, v.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return v.do(req)
}

// pass runs the whole challenge for path the way a browser would: GET it,
// read the form action from the challenge page, submit the token there, and
// follow the redirect. It returns the final response body.
func (v *visitor) pass(path string) string {
	v.t.Helper()
	resp, body := v.get(path)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "cf-turnstile") {
		v.t.Fatalf("GET %s: got %d, want the challenge page", path, resp.StatusCode)
	}
	action := formAction(v.t, body)
	if action != path {
		v.t.Errorf("GET %s: challenge form posts to %q, want the requested URL", path, action)
	}

	resp, _ = v.post(action, solve("good"))
	if resp.StatusCode != http.StatusSeeOther {
		v.t.Fatalf("POST %s: got %d, want 303 (verification did not reach turnstile)", action, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != path {
		v.t.Errorf("POST %s: redirected to %q, want %q", action, loc, path)
	}

	resp, body = v.get(path)
	if resp.StatusCode != http.StatusOK {
		v.t.Fatalf("GET %s after clearance: got %d, want 200", path, resp.StatusCode)
	}
	return body
}

func formAction(t *testing.T, page string) string {
	t.Helper()
	_, rest, ok := strings.Cut(page, `<form id="bp-turnstile" method="POST" action="`)
	if !ok {
		t.Fatalf("no challenge form in page:\n%s", page)
	}
	action, _, _ := strings.Cut(rest, `"`)
	return strings.ReplaceAll(action, "&amp;", "&")
}

func integrationFake(t *testing.T) *fakeSiteverify {
	t.Helper()
	f := &fakeSiteverify{hostname: "127.0.0.1", action: turnstileAction}
	useSiteverify(t, f)
	return f
}

// TestIntegrationTryFiles is the single-page-app setup from the review:
// try_files rewrites every unknown path to /index.html. The challenge must
// still post back to, and return the visitor to, the URL they asked for.
func TestIntegrationTryFiles(t *testing.T) {
	integrationFake(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("spa-shell"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := startCaddy(t, `
	root * `+root+`
	try_files {path} /index.html
	%TURNSTILE%
	file_server`)

	if body := newVisitor(t, base).pass("/articles/hello?ref=x"); body != "spa-shell" {
		t.Errorf("after clearance got %q, want the SPA shell", body)
	}
}

// TestIntegrationRewriteInsideRoute covers a turnstile that, inside a route
// block, explicitly runs after a rewrite. The form still posts to the
// original URL, which the same rewrite takes back to the same handler.
func TestIntegrationRewriteInsideRoute(t *testing.T) {
	integrationFake(t)
	base := startCaddy(t, `
	route {
		rewrite * /internal{uri}
		%TURNSTILE%
		respond "served {path}"
	}`)

	if body := newVisitor(t, base).pass("/page?q=1"); body != "served /internal/page" {
		t.Errorf("after clearance got %q", body)
	}
}

// TestIntegrationHandlePath: handle_path strips the prefix before the inner
// routes run, so the handler only sees /x. The visitor asked for /app/x.
func TestIntegrationHandlePath(t *testing.T) {
	integrationFake(t)
	base := startCaddy(t, `
	handle_path /app/* {
		%TURNSTILE%
		respond "app {path}"
	}
	respond "public"`)

	v := newVisitor(t, base)
	if body := v.pass("/app/x"); body != "app /x" {
		t.Errorf("after clearance got %q", body)
	}
	if _, body := newVisitor(t, base).get("/other"); body != "public" {
		t.Errorf("unscoped path: got %q", body)
	}
}

// TestIntegrationPathScoped checks matcher-scoped turnstile, both inline and
// named: the verification POST must reach the handler, unprotected paths must
// not be challenged, and a rewrite (here try_files) must not lift the
// protection off a protected URL.
func TestIntegrationPathScoped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("shell"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]string{
		"inline": `turnstile /protected/* {
		site_key   ` + testSiteKey + `
		secret_key ` + testSecretKey + `
	}`,
		"named": `@gated path /protected/*
	turnstile @gated {
		site_key   ` + testSiteKey + `
		secret_key ` + testSecretKey + `
	}`,
	} {
		t.Run(name, func(t *testing.T) {
			integrationFake(t)
			base := startCaddy(t, `
	root * `+root+`
	try_files {path} /index.html
	`+scope+`
	file_server`)

			if resp, body := newVisitor(t, base).get("/public/page"); resp.StatusCode != http.StatusOK || body != "shell" {
				t.Errorf("unprotected path: got %d %q, want 200 without a challenge", resp.StatusCode, body)
			}
			// /protected/page does not exist on disk, so try_files rewrites
			// it to /index.html — which the matcher must not see.
			if body := newVisitor(t, base).pass("/protected/page"); body != "shell" {
				t.Errorf("after clearance got %q", body)
			}
		})
	}
}

// TestIntegrationHandleBlocks: turnstile inside one handle block protects
// only that block, and its verification lands in the same block.
func TestIntegrationHandleBlocks(t *testing.T) {
	integrationFake(t)
	base := startCaddy(t, `
	handle /members/* {
		%TURNSTILE%
		respond "members"
	}
	handle {
		respond "open"
	}`)

	if body := newVisitor(t, base).pass("/members/area"); body != "members" {
		t.Errorf("after clearance got %q", body)
	}
	if resp, body := newVisitor(t, base).get("/"); resp.StatusCode != http.StatusOK || body != "open" {
		t.Errorf("other handle block: got %d %q", resp.StatusCode, body)
	}
}

// TestIntegrationStrictCSP: a site-wide CSP from a header directive would
// block Turnstile; the challenge page must carry its own policy, and the
// site's policy must still apply once the visitor is through.
func TestIntegrationStrictCSP(t *testing.T) {
	integrationFake(t)
	const sitePolicy = "default-src 'self'; script-src 'self'"
	base := startCaddy(t, `
	header Content-Security-Policy "`+sitePolicy+`"
	%TURNSTILE%
	respond "app"`)

	v := newVisitor(t, base)
	resp, body := v.get("/")
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == sitePolicy || !strings.Contains(csp, "https://challenges.cloudflare.com") {
		t.Fatalf("challenge page CSP = %q, want the challenge's own policy", csp)
	}
	nonce := noncePattern.FindStringSubmatch(csp)
	if nonce == nil || !strings.Contains(body, `nonce="`+nonce[1]+`"`) {
		t.Errorf("challenge scripts do not carry the CSP nonce")
	}

	v.pass("/")
	resp, _ = v.get("/")
	if got := resp.Header.Get("Content-Security-Policy"); got != sitePolicy {
		t.Errorf("app response CSP = %q, want the site's own %q", got, sitePolicy)
	}
}

// TestIntegrationFailedVerificationRecovers: after a rejected token the
// visitor has a link back, and following it gives a fresh challenge.
func TestIntegrationFailedVerificationRecovers(t *testing.T) {
	integrationFake(t)
	base := startCaddy(t, "\t%TURNSTILE%\n\trespond \"app\"")

	v := newVisitor(t, base)
	resp, body := v.post("/deep/page?x=1", solve("bad"))
	if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
		t.Fatalf("bad token: got %d with %d cookies", resp.StatusCode, len(resp.Cookies()))
	}
	if !strings.Contains(body, `href="/deep/page?x=1"`) {
		t.Fatalf("failure page has no retry link to the original URL:\n%s", body)
	}
	if body := v.pass("/deep/page?x=1"); body != "app" {
		t.Errorf("after retrying got %q", body)
	}
}

// TestIntegrationDirectiveOrder pins down where the Caddyfile puts the
// handlers: ja4, bot_policy, turnstile, in that order, and all of them
// before anything that rewrites the URL.
func TestIntegrationDirectiveOrder(t *testing.T) {
	cfg := `example.com {
	file_server
	try_files {path} /index.html
	rewrite /a /b
	redir /old /new
	turnstile {
		site_key a
		secret_key b
	}
	bot_policy {
		block x
	}
	header X-Test 1
	ja4
}`
	adapted, _, err := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}.Adapt([]byte(cfg), nil)
	if err != nil {
		t.Fatal(err)
	}
	js := string(adapted)
	order := []string{`"handler":"headers"`, `"handler":"ja4"`, `"handler":"bot_policy"`, `"handler":"turnstile"`, `"handler":"static_response"`, `"handler":"rewrite"`, `"handler":"file_server"`}
	last := -1
	for _, h := range order {
		i := strings.Index(js, h)
		if i < 0 {
			t.Fatalf("%s missing from adapted config:\n%s", h, js)
		}
		if i < last {
			t.Errorf("%s is out of order in:\n%s", h, js)
		}
		last = i
	}
}

// Verification is a POST back to the protected URL. A GET-only method
// matcher challenges the page but cannot receive its own verification.
func TestIntegrationMethodMatchersForVerification(t *testing.T) {
	for _, tc := range []struct {
		name, methods string
		works         bool
	}{
		{"GET only", "GET", false},
		{"GET and POST", "GET POST", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := integrationFake(t)
			base := startCaddy(t, `
	@pages {
		path /members/*
		method `+tc.methods+`
	}
	turnstile @pages {
		site_key `+testSiteKey+`
		secret_key `+testSecretKey+`
	}
	respond "app"`)

			v := newVisitor(t, base)
			resp, body := v.get("/members/home")
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "cf-turnstile") {
				t.Fatalf("GET: got %d, expected a challenge", resp.StatusCode)
			}
			resp, _ = v.post("/members/home", solve("good"))
			if tc.works {
				if resp.StatusCode != http.StatusSeeOther || f.calls.Load() != 1 {
					t.Fatalf("POST: got %d, verify calls %d, expected 303 and one verification", resp.StatusCode, f.calls.Load())
				}
				resp, body = v.get("/members/home")
				if resp.StatusCode != http.StatusOK || body != "app" {
					t.Errorf("GET after clearance: got %d %q", resp.StatusCode, body)
				}
			} else {
				if resp.StatusCode == http.StatusSeeOther || f.calls.Load() != 0 {
					t.Fatalf("GET-only matcher unexpectedly verified: status=%d calls=%d", resp.StatusCode, f.calls.Load())
				}
				resp, body = v.get("/members/home")
				if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "cf-turnstile") {
					t.Errorf("GET after bypassed POST: got %d %q; expected another challenge", resp.StatusCode, body)
				}
			}
		})
	}
}

// Operators using bind_fingerprint with HTTP/3 migration need an h1/h2-only
// deployment option; verify the documented Caddy global protocols syntax.
func TestIntegrationHTTP3DisabledConfig(t *testing.T) {
	cfg := `{
		servers {
			protocols h1 h2
			listener_wrappers {
				ja4
				tls
			}
		}
	}
	example.com {
		ja4
		turnstile {
			site_key ` + testSiteKey + `
			secret_key ` + testSecretKey + `
			bind_fingerprint
		}
		respond "app"
	}`
	adapted, _, err := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}.Adapt([]byte(cfg), nil)
	if err != nil {
		t.Fatalf("h1/h2 fallback does not adapt: %v", err)
	}
	if !strings.Contains(string(adapted), `"protocols":["h1","h2"]`) {
		t.Errorf("h1/h2 fallback did not disable h3: %s", adapted)
	}
}

// A browser visits two separately configured, path-scoped Turnstile handlers
// on the same hostname and keeps both cookies without any overwrites.
func TestIntegrationIndependentProtectedRoutes(t *testing.T) {
	f := integrationFake(t)
	base := startCaddy(t, `
	handle /alpha/* {
		turnstile {
			site_key `+testSiteKey+`
			secret_key `+testSecretKey+`
			clearance_key `+strings.Repeat("a", 32)+`
		}
		respond "alpha"
	}
	handle /beta/* {
		turnstile {
			site_key `+testSiteKey+`
			secret_key `+testSecretKey+`
			clearance_key `+strings.Repeat("b", 32)+`
		}
		respond "beta"
	}`)
	v := newVisitor(t, base)
	if got := v.pass("/alpha/a"); got != "alpha" {
		t.Errorf("alpha: %q", got)
	}
	f.redeemed.Store(false)
	if got := v.pass("/beta/b"); got != "beta" {
		t.Errorf("beta: %q", got)
	}
	if len(v.cookies) != 2 || v.cookies[0].Name == v.cookies[1].Name {
		t.Fatalf("two independent policies must give two cookie slots: %v", v.cookies)
	}
	for _, tc := range []struct{ path, want string }{{"/alpha/a", "alpha"}, {"/beta/b", "beta"}, {"/alpha/a", "alpha"}} {
		resp, body := v.get(tc.path)
		if resp.StatusCode != http.StatusOK || body != tc.want {
			t.Errorf("revisit %s: got %d %q", tc.path, resp.StatusCode, body)
		}
	}
}
