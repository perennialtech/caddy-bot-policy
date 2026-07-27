package botpolicy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func newTestPolicy(t *testing.T, onMissingFingerprint string, blocked ...string) *BotPolicy {
	t.Helper()
	set := make(map[string]bool, len(blocked))
	for _, fp := range blocked {
		set[fp] = true
	}
	return &BotPolicy{
		VarName:              "ja4",
		OnMissingFingerprint: onMissingFingerprint,
		Action:               "block-403",
		blocked:              set,
		logger:               zap.NewNop(),
	}
}

var passThrough = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	return nil
})

func doRequest(t *testing.T, bp *BotPolicy, fingerprint string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"

	varMap := make(map[string]any)
	if fingerprint != "" {
		varMap[bp.VarName] = fingerprint
	}
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, varMap)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	if err := bp.ServeHTTP(rec, req, passThrough); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	return rec
}

func TestServeHTTPBlocksMatchingFingerprint(t *testing.T) {
	bp := newTestPolicy(t, "open", "t13d1517h2_8daaf6152771_b6f405a00624")

	rec := doRequest(t, bp, "t13d1517h2_8daaf6152771_b6f405a00624")
	if rec.Code != http.StatusForbidden {
		t.Errorf("blocked fingerprint: got %d, want 403", rec.Code)
	}
	if rec.Header().Get("X-Block-Id") == "" {
		t.Error("expected X-Block-Id header to be set on a blocked response")
	}
}

func TestServeHTTPPassesNonMatchingFingerprint(t *testing.T) {
	bp := newTestPolicy(t, "open", "t13d1517h2_8daaf6152771_b6f405a00624")

	rec := doRequest(t, bp, "q13d0312h3_55b375c5d22e_cd8dafe46ac5")
	if rec.Code != http.StatusOK {
		t.Errorf("non-matching fingerprint: got %d, want 200", rec.Code)
	}
}

func TestServeHTTPOnMissingFingerprintOpenVsClosed(t *testing.T) {
	open := newTestPolicy(t, "open", "t13d1517h2_8daaf6152771_b6f405a00624")
	rec := doRequest(t, open, "")
	if rec.Code != http.StatusOK {
		t.Errorf("on_missing_fingerprint open: got %d, want 200 (fail open)", rec.Code)
	}

	closed := newTestPolicy(t, "closed", "t13d1517h2_8daaf6152771_b6f405a00624")
	rec = doRequest(t, closed, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("on_missing_fingerprint closed: got %d, want 403 (fail closed)", rec.Code)
	}
}

func TestProvisionErrorsOnEmptyBlockList(t *testing.T) {
	d := caddyfile.NewTestDispenser(`bot_policy {
		on_missing_fingerprint open
	}`)
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if err := bp.Provision(caddy.Context{}); err == nil {
		t.Error("expected Provision to error on an empty block list")
	}
}

func TestProvisionErrorsOnInvalidAction(t *testing.T) {
	d := caddyfile.NewTestDispenser(`bot_policy {
		block  t13d1517h2_8daaf6152771_b6f405a00624
		action redirect
	}`)
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if err := bp.Provision(caddy.Context{}); err == nil {
		t.Error("expected Provision to error on an unsupported action")
	}
}
