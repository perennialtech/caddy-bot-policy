package botpolicy

import (
	"context"
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
		set        func(string, string, string)
		clear      func(string)
	}{
		{"TCP", "192.0.2.21:3131", 2, conns.setPair, conns.delete},
		{"QUIC", "192.0.2.21:3132", 3, quicConns.setPair, quicConns.delete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			if err := h.Provision(caddy.Context{}); err != nil {
				t.Fatal(err)
			}
			tc.set(tc.addr, "exact-ja4", "normalized-ja4")
			defer tc.clear(tc.addr)

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.ProtoMajor, r.RemoteAddr = tc.proto, tc.addr
			r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
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
