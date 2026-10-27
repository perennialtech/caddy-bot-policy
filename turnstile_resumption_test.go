package botpolicy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// This uses real TLS 1.3 handshakes with one ticket cache and the actual
// listener/HTTP handlers. Synthetic JA4 strings cannot prove that the
// resumption-sensitive extensions are being removed.
func TestBoundClearanceSurvivesTLSResumption(t *testing.T) {
	verifier := newFake(t, "127.0.0.1", turnstileAction)
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey, BindFingerprintVar: "ja4_bind"}
	if err := ts.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	ja4Handler := &Handler{}
	if err := ja4Handler.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener((&ListenerWrapper{MaxCaptureBytes: defaultMaxCaptureBytes}).WrapListener(ln), &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	})
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
		err := ja4Handler.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			if exact, ok := caddyhttp.GetVar(r.Context(), "ja4").(string); ok {
				w.Header().Set("X-Exact-JA4", exact)
			}
			if bind, ok := caddyhttp.GetVar(r.Context(), "ja4_bind").(string); ok {
				w.Header().Set("X-Bind-JA4", bind)
			}
			return ts.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "ok")
				return nil
			}))
		}))
		if err != nil {
			t.Errorf("handler: %v", err)
		}
	})}
	go func() { _ = server.Serve(tlsLn) }()
	t.Cleanup(func() { _ = server.Close(); _ = tlsLn.Close() })

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		ServerName: "example.com", InsecureSkipVerify: true, // test-only cert
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		NextProtos:         []string{"http/1.1"},
	}}
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(transport.CloseIdleConnections)
	base := "https://" + ln.Addr().String()

	do := func(method string, body url.Values) *http.Response {
		t.Helper()
		var requestBody io.Reader
		if body != nil {
			requestBody = strings.NewReader(body.Encode())
		}
		req, err := http.NewRequest(method, base+"/", requestBody)
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.Header.Get("X-Bind-JA4") == "" || resp.Header.Get("X-Exact-JA4") == "" {
			t.Fatalf("missing fingerprints: exact=%q bind=%q", resp.Header.Get("X-Exact-JA4"), resp.Header.Get("X-Bind-JA4"))
		}
		return resp
	}

	first := do(http.MethodGet, nil)
	if first.StatusCode != http.StatusForbidden || first.TLS.DidResume {
		t.Fatalf("initial GET: %d resumed=%v", first.StatusCode, first.TLS.DidResume)
	}
	solved := do(http.MethodPost, solve("good"))
	if solved.StatusCode != http.StatusSeeOther {
		t.Fatalf("solve: %d", solved.StatusCode)
	}
	if resp := do(http.MethodGet, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("first cleared GET: %d", resp.StatusCode)
	}
	if n := verifier.calls.Load(); n != 1 {
		t.Fatalf("siteverify calls=%d; want 1", n)
	}

	transport.CloseIdleConnections()
	resumed := do(http.MethodGet, nil)
	if !resumed.TLS.DidResume {
		t.Fatal("TLS client did not resume the saved session; the regression is not being exercised")
	}
	if resumed.Header.Get("X-Exact-JA4") == first.Header.Get("X-Exact-JA4") {
		t.Fatalf("test needs differing exact JA4s across handshakes: %q", first.Header.Get("X-Exact-JA4"))
	}
	if resumed.Header.Get("X-Bind-JA4") != first.Header.Get("X-Bind-JA4") {
		t.Fatalf("bound fingerprint changed: full=%q resumed=%q", first.Header.Get("X-Bind-JA4"), resumed.Header.Get("X-Bind-JA4"))
	}
	if resumed.StatusCode != http.StatusOK || verifier.calls.Load() != 1 {
		t.Fatalf("resumed visit should reuse the clearance, got HTTP %d and %d siteverify calls", resumed.StatusCode, verifier.calls.Load())
	}
}
