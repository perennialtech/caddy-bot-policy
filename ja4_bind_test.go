package botpolicy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestJA4PublishesDistinctExactAndBoundVariables(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
		proto      int
	}{
		{"TCP", "192.0.2.21:3131", 2},
		{"QUIC", "192.0.2.21:3132", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			if err := h.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.ProtoMajor, r.RemoteAddr = tc.proto, tc.addr
			ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
			if tc.proto == 3 {
				slot := new(quicFingerprint)
				slot.Store(&fingerprints{ja4: "exact-ja4", bind: "normalized-ja4"})
				ctx = context.WithValue(ctx, quicFingerprintKey{}, slot)
			} else {
				local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
				key := tcpConnectionKey(tc.addr, local.String())
				ctx = context.WithValue(ctx, http.LocalAddrContextKey, local)
				conns.setPair(key, "exact-ja4", "normalized-ja4")
				defer conns.delete(key)
			}
			r = r.WithContext(ctx)
			w := httptest.NewRecorder()
			err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
				if got := caddyhttp.GetVar(r.Context(), "ja4"); got != "exact-ja4" {
					t.Errorf("raw JA4 = %v", got)
				}
				if got := caddyhttp.GetVar(r.Context(), "ja4_bind"); got != "normalized-ja4" {
					t.Errorf("bind JA4 = %v", got)
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJA4BindVariableConfiguration(t *testing.T) {
	d := caddyfile.NewTestDispenser("ja4 {\nvar_name exact_ja4\nbind_var_name clearance_profile\n}")
	h := &Handler{}
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if h.VarName != "exact_ja4" || h.BindVarName != "clearance_profile" {
		t.Fatalf("Caddyfile variables: %+v", h)
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, raw, bind string
	}{
		{"same variables", "fp", "fp"},
		{"invalid bind variable", "ja4", "contains space"},
		{"invalid exact variable", "bad{var}", "ja4_bind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{VarName: tc.raw, BindVarName: tc.bind}
			if err := h.Provision(caddy.Context{}); err == nil {
				t.Fatal("expected invalid variable configuration to fail")
			}
		})
	}
}

func TestTurnstileSiteverifyTransportCapacity(t *testing.T) {
	ts := &Turnstile{SiteKey: testSiteKey, SecretKey: testSecretKey, MaxPendingVerifications: 123}
	if err := ts.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	defer ts.Cleanup()
	if ts.ownedTransport == nil || ts.ownedTransport.MaxIdleConnsPerHost != 123 || ts.ownedTransport.MaxIdleConns < 123 {
		t.Fatalf("inadequate siteverify transport capacity: %+v", ts.ownedTransport)
	}
}
