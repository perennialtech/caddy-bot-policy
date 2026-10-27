package botpolicy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// A preexisting Caddy var is not evidence of a wire fingerprint. This
// covers both an absent listener wrapper and a variable poisoned by an
// earlier vars/map directive.
func TestMissingWireFingerprintCannotUseClaimedRequestVariable(t *testing.T) {
	verifier := newFake(t, testHost, turnstileAction)
	ts := newTestTurnstile(t, true)
	h := &Handler{}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "https://example.com/protected", nil)
	r.Host = testHost
	r.RemoteAddr = "198.51.100.22:45454"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}))
	values := map[string]any{"ja4": "header-supplied", "ja4_bind": "header-supplied"}
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, values))

	w := httptest.NewRecorder()
	err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if got := caddyhttp.GetVar(r.Context(), "ja4"); got != "" {
			t.Errorf("stale exact JA4 survived: %v", got)
		}
		if got := caddyhttp.GetVar(r.Context(), "ja4_bind"); got != "" {
			t.Errorf("stale bind JA4 survived: %v", got)
		}
		if fp, bound := ts.fingerprint(r); !bound || fp != "" {
			t.Errorf("untrusted fingerprint accepted: %q, bound=%t", fp, bound)
		}
		// Supply a valid form token; the refusal must occur before siteverify.
		r2 := httptest.NewRequest(http.MethodPost, "https://example.com/protected", nil)
		r2 = r2.WithContext(r.Context())
		r2.PostForm = solve("good")
		return ts.verify(w, r2)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusForbidden || anyCookie(w) || verifier.calls.Load() != 0 {
		t.Fatalf("spoofed fingerprint accepted: status=%d cookies=%v verifier calls=%d", w.Code, w.Result().Cookies(), verifier.calls.Load())
	}

	// Without ja4 in the route there isn't even a trusted context value.
	raw := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	raw = raw.WithContext(context.WithValue(raw.Context(), caddyhttp.VarsCtxKey,
		map[string]any{"ja4": "spoof", "ja4_bind": "spoof"}))
	if fp, bound := ts.fingerprint(raw); !bound || fp != "" {
		t.Fatalf("missing ja4 handler accepted claimed JA4: %q, bound=%t", fp, bound)
	}
}

func TestBoundClearanceIgnoresVarTamperingAfterJA4(t *testing.T) {
	ts := newTestTurnstile(t, true)
	h := &Handler{}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	remote, local := "198.51.100.23:45454", "127.0.0.1:443"
	key := tcpConnectionKey(remote, local)
	conns.setPair(key, "genuine", "stable")
	defer conns.delete(key)
	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Host, r.RemoteAddr = testHost, remote
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}))
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
	err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		issued := ts.mintClearance(time.Now(), r)
		caddyhttp.SetVar(r.Context(), "ja4", "attacker-value")
		caddyhttp.SetVar(r.Context(), "ja4_bind", "attacker-value")
		if fp, bound := ts.fingerprint(r); !bound || fp != "genuine" {
			t.Errorf("request var overwrote trusted fingerprint: %q, bound=%t", fp, bound)
		}
		if !ts.validClearance(issued, r) {
			t.Error("valid clearance broke after request variable tampering")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCPFingerprintLookupIncludesLocalEndpoint(t *testing.T) {
	const remote = "198.51.100.24:45678"
	keyA := tcpConnectionKey(remote, "127.0.0.1:443")
	keyB := tcpConnectionKey(remote, "127.0.0.1:8443")
	if keyA == keyB || keyA == "" || keyB == "" {
		t.Fatalf("TCP endpoint pair not unique: %q %q", keyA, keyB)
	}
	conns.setPair(keyA, "a", "bind-a")
	conns.setPair(keyB, "b", "bind-b")
	defer conns.delete(keyA)
	defer conns.delete(keyB)

	h := &Handler{}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		port int
		want string
	}{{443, "bind-a"}, {8443, "bind-b"}} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey,
			&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: tc.port}))
		r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
		err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
			if fp, ok := r.Context().Value(observedFingerprintKey{}).(observedFingerprint); !ok || fp.bind != tc.want {
				t.Errorf("port %d got %+v, want %q", tc.port, fp, tc.want)
			}
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	conns.delete(keyB)
	if got := conns.getBind(keyA); got != "bind-a" {
		t.Fatalf("closing other local endpoint deleted surviving connection: %q", got)
	}
}

// Merely overwriting the UDP-address table must never create authority
// to use an HTTP/3 bound clearance.
func TestForgedQUICInitialCannotAuthorizeBoundClearance(t *testing.T) {
	ts := newTestTurnstile(t, true)
	r := newTurnstileRequest(http.MethodGet, "/private", testFPQUIC, nil)
	r.ProtoMajor = 3
	addr := "198.51.100.25:4433"
	r.RemoteAddr = addr
	quicConns.setPair(addr, "forged-exact", testFPQUIC)
	defer quicConns.delete(addr)
	c := &http.Cookie{Name: ts.cookieName(testFPQUIC, true),
		Value: ts.mintClearance(time.Now(), newTurnstileRequest(http.MethodGet, "/private", testFPQUIC, nil))}
	r.AddCookie(c)
	if ts.cleared(r) {
		t.Fatal("HTTP/3 accepted a cookie using unauthenticated QUIC Initial data")
	}
	if fp, bound := ts.fingerprint(r); !bound || fp != "" {
		t.Fatalf("HTTP/3 attributed unauthenticated data to live connection: %q", fp)
	}
}
