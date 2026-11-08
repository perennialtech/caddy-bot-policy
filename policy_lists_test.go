package botpolicy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func parsePolicyLists(t *testing.T, body string) *BotPolicy {
	t.Helper()
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n" + body + "\n}")); err != nil {
		t.Fatal(err)
	}
	if err := bp.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if err := bp.Validate(); err != nil {
		t.Fatal(err)
	}
	return &bp
}

func TestPolicyLists(t *testing.T) {
	for _, tt := range []struct {
		name, rules, ip, fingerprint string
		status                       int
		challenge                    bool
	}{
		{"IPv4 blacklist", "blacklist 203.0.113.0/24", "203.0.113.7", "", 403, false},
		{"IPv6 blacklist", "blacklist 2001:db8::/32", "2001:db8:1::7", "", 403, false},
		{"single IPv4 blacklist", "blacklist 203.0.113.7", "203.0.113.7", "", 403, false},
		{"single IPv6 blacklist", "blacklist 2001:db8::7", "2001:db8::7", "", 403, false},
		{"IPv4 whitelist", "whitelist 203.0.113.0/24", "203.0.113.7", testFP, 200, false},
		{"IPv6 whitelist", "whitelist 2001:db8::/32", "2001:db8:1::7", testFP, 200, false},
		{"single IPv4 whitelist", "whitelist 203.0.113.7", "203.0.113.7", "", 200, false},
		{"single IPv6 whitelist", "whitelist 2001:db8::7", "2001:db8::7", "", 200, false},
		{"whitelist bypasses missing fingerprint", "whitelist 203.0.113.7\non_missing_fingerprint closed", "203.0.113.7", "", 200, false},
		{"blacklist beats narrower whitelist", "blacklist 203.0.113.0/24\nwhitelist 203.0.113.7", "203.0.113.7", "", 403, false},
		{"blacklist beats broader whitelist", "whitelist 2001:db8::/32\nblacklist 2001:db8::7", "2001:db8::7", "", 403, false},
		{"unmatched JA4 blocked", "whitelist 198.51.100.0/24\nblacklist " + testFP, "203.0.113.7", testFP, 403, false},
		{"unmatched gets challenge", "blacklist 198.51.100.0/24", "203.0.113.7", "", 403, true},
		{"repeated and multiple entries", "blacklist 198.51.100.7 2001:db8::/32\nblacklist 203.0.113.7", "203.0.113.7", "", 403, false},
		{"JA4 whitelist", "whitelist " + testFP, "203.0.113.7", testFP, 200, false},
		{"QUIC JA4 whitelist", "whitelist " + testFPQUIC, "203.0.113.7", testFPQUIC, 200, false},
		{"JA4 blacklist", "blacklist " + testFP, "203.0.113.7", testFP, 403, false},
		{"JA4 blacklist beats IP whitelist", "whitelist 203.0.113.0/24\nblacklist " + testFP, "203.0.113.7", testFP, 403, false},
		{"IP blacklist beats JA4 whitelist", "whitelist " + testFP + "\nblacklist 203.0.113.7", "203.0.113.7", testFP, 403, false},
		{"JA4 blacklist beats JA4 whitelist", "whitelist " + testFP + "\nblacklist " + testFP, "203.0.113.7", testFP, 403, false},
		{"mixed whitelist entries", "whitelist 198.51.100.7 " + testFP + " 2001:db8::/32", "203.0.113.7", testFP, 200, false},
		{"mixed blacklist entries", "blacklist 198.51.100.7 " + testFP + " 2001:db8::/32", "203.0.113.7", testFP, 403, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bp := parsePolicyLists(t, tt.rules)
			ts := newTestTurnstile(t, true)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", tt.fingerprint, nil)
			req.TLS.HandshakeComplete = true
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tt.ip)
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return ts.ServeHTTP(w, r, passThrough)
			})
			if err := bp.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tt.status || strings.Contains(rec.Body.String(), "cf-turnstile") != tt.challenge {
				t.Fatalf("got %d %q, want status %d, challenge %v", rec.Code, rec.Body.String(), tt.status, tt.challenge)
			}
			if tt.status == http.StatusForbidden && !tt.challenge && !strings.HasPrefix(rec.Header().Get("X-Block-Id"), "bp-") {
				t.Fatalf("expected bot_policy block, got headers %v", rec.Header())
			}
		})
	}
}

func TestPolicyBlacklistOverridesClearance(t *testing.T) {
	for _, entry := range []string{testFP, "203.0.113.0/24"} {
		t.Run(entry, func(t *testing.T) {
			bp := parsePolicyLists(t, "blacklist "+entry)
			ts := newTestTurnstile(t, true)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", testFP, nil)
			req.TLS.HandshakeComplete = true
			req.AddCookie(&http.Cookie{Name: ts.cookieName(testFP, true), Value: ts.mintClearance(ts.now(), req)})
			if !ts.cleared(req) {
				t.Fatal("test request must have valid clearance")
			}
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return ts.ServeHTTP(w, r, passThrough)
			})
			if err := bp.ServeHTTP(rec, req, next); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusForbidden || !strings.HasPrefix(rec.Header().Get("X-Block-Id"), "bp-") {
				t.Fatalf("clearance bypassed blacklist: %d, %v", rec.Code, rec.Header())
			}
		})
	}
}

func TestPolicyListsInvalidConfig(t *testing.T) {
	for _, directive := range []string{"whitelist", "blacklist"} {
		t.Run(directive+" requires arguments", func(t *testing.T) {
			var bp BotPolicy
			if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n" + directive + "\n}")); err == nil {
				t.Fatal("accepted empty policy list")
			}
		})
		for _, value := range []string{"not-an-ip", "203.0.113.0/33", "2001:db8::/129", "t13d1517h2_bad_b6f405a00624"} {
			t.Run(directive+"/"+value, func(t *testing.T) {
				var bp BotPolicy
				if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n" + directive + " " + value + "\n}")); err != nil {
					t.Fatal(err)
				}
				if err := bp.Provision(caddy.Context{}); err == nil {
					t.Fatal("accepted invalid JA4, IP or CIDR")
				}
			})
		}
	}
}
