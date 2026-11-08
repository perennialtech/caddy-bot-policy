package botpolicy

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

var passThrough = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func TestProvisionErrorsOnEmptyPolicyLists(t *testing.T) {
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n}")); err != nil {
		t.Fatal(err)
	}
	if err := bp.Provision(caddy.Context{}); err == nil {
		t.Error("expected Provision to reject empty policy lists")
	}
}

func TestProvisionErrorsOnInvalidAction(t *testing.T) {
	d := caddyfile.NewTestDispenser(`bot_policy {
        blacklist 203.0.113.0/24
        action redirect
    }`)
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if err := bp.Provision(caddy.Context{}); err == nil {
		t.Error("expected Provision to reject unsupported action")
	}
}

func TestBlockIDFormat(t *testing.T) {
	for _, prefix := range []string{"bp-", "ts-"} {
		id := newBlockID(prefix)
		suffix, ok := strings.CutPrefix(id, prefix)
		if !ok || len(suffix) != 32 {
			t.Fatalf("block ID %q: want %s followed by 32 hex characters", id, prefix)
		}
		if _, err := hex.DecodeString(suffix); err != nil {
			t.Fatalf("block ID %q: %v", id, err)
		}
	}
}

func TestPolicyBlockedResponse(t *testing.T) {
	bp := parsePolicyLists(t, "blacklist 203.0.113.7")
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req.TLS.HandshakeComplete = true
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	rec := httptest.NewRecorder()
	if err := bp.ServeHTTP(rec, req, passThrough); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden || !strings.HasPrefix(rec.Header().Get("X-Block-Id"), "bp-") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("blocked response: %d %v", rec.Code, rec.Header())
	}
}
