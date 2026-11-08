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
		name, rules, ip string
		status          int
		challenge       bool
	}{
		{"IPv4 blacklist", "blacklist 203.0.113.0/24", "203.0.113.7", 403, false},
		{"IPv6 blacklist", "blacklist 2001:db8::/32", "2001:db8:1::7", 403, false},
		{"single IPv4 blacklist", "blacklist 203.0.113.7", "203.0.113.7", 403, false},
		{"single IPv6 blacklist", "blacklist 2001:db8::7", "2001:db8::7", 403, false},
		{"IPv4 whitelist", "whitelist 203.0.113.0/24", "203.0.113.7", 200, false},
		{"IPv6 whitelist", "whitelist 2001:db8::/32", "2001:db8:1::7", 200, false},
		{"single IPv4 whitelist", "whitelist 203.0.113.7", "203.0.113.7", 200, false},
		{"single IPv6 whitelist", "whitelist 2001:db8::7", "2001:db8::7", 200, false},
		{"blacklist beats narrower whitelist", "blacklist 203.0.113.0/24\nwhitelist 203.0.113.7", "203.0.113.7", 403, false},
		{"blacklist beats broader whitelist", "whitelist 2001:db8::/32\nblacklist 2001:db8::7", "2001:db8::7", 403, false},
		{"unmatched gets challenge", "blacklist 198.51.100.0/24", "203.0.113.7", 403, true},
		{"repeated entries", "blacklist 198.51.100.7 2001:db8::/32\nblacklist 203.0.113.7", "203.0.113.7", 403, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bp := parsePolicyLists(t, tt.rules)
			ts := newTestTurnstile(t)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
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
			if tt.status == 403 && !tt.challenge && !strings.HasPrefix(rec.Header().Get("X-Block-Id"), "bp-") {
				t.Fatalf("expected policy block, got %v", rec.Header())
			}
		})
	}
}

func TestPolicyUserAgentRules(t *testing.T) {
	for _, tt := range []struct {
		name, rules, ip, userAgent string
		status                     int
		challenge                  bool
	}{
		{"UA whitelist bypasses Turnstile", `whitelist "ua:(?i)googlebot"`, "203.0.113.7", "Googlebot/2.1", 200, false},
		{"UA blacklist", "blacklist ua:BadBot", "203.0.113.7", "NotBadBot/1.0", 403, false},
		{"case-sensitive mismatch", "blacklist ua:BadBot", "203.0.113.7", "badbot/1.0", 403, true},
		{"unmatched UA", "blacklist ua:BadBot", "203.0.113.7", "GoodBot/1.0", 403, true},
		{"missing UA never matches wildcard blacklist", "blacklist ua:.*", "203.0.113.7", "", 403, true},
		{"missing UA never matches wildcard whitelist", "whitelist ua:.*", "203.0.113.7", "", 403, true},
		{"anchored mismatch", "blacklist ua:^BadBot$", "203.0.113.7", "BadBot/1.0", 403, true},
		{"quoted pattern with space", `whitelist "ua:Friendly Browser"`, "203.0.113.7", "Friendly Browser/1.0", 200, false},
		{"UA blacklist beats IP whitelist", "whitelist 203.0.113.0/24\nblacklist ua:BadBot", "203.0.113.7", "BadBot/1.0", 403, false},
		{"IP blacklist beats UA whitelist", "blacklist 203.0.113.0/24\nwhitelist ua:GoodBot", "203.0.113.7", "GoodBot/1.0", 403, false},
		{"UA blacklist beats UA whitelist", "whitelist ua:Bot\nblacklist ua:BadBot", "203.0.113.7", "BadBot/1.0", 403, false},
		{"mixed whitelist", "whitelist 198.51.100.7 ua:GoodBot 2001:db8::/32", "203.0.113.7", "GoodBot/1.0", 200, false},
		{"mixed blacklist", "blacklist 198.51.100.7 ua:BadBot 2001:db8::/32", "203.0.113.7", "BadBot/1.0", 403, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bp := parsePolicyLists(t, tt.rules)
			ts := newTestTurnstile(t)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
			req.TLS.HandshakeComplete = true
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
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
		})
	}
}

func TestPolicyIgnoresForwardedUserAgent(t *testing.T) {
	bp := parsePolicyLists(t, "blacklist ua:BadBot")
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req.Header.Set("User-Agent", "GoodBot/1.0")
	req.Header.Set("X-Forwarded-User-Agent", "BadBot/1.0")
	rec := httptest.NewRecorder()
	if err := bp.ServeHTTP(rec, req, passThrough); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("forwarded User-Agent influenced policy: got %d, want 200", rec.Code)
	}
}

func TestPolicyBlacklistOverridesClearance(t *testing.T) {
	for _, entry := range []string{"203.0.113.0/24", "ua:BadBot"} {
		t.Run(entry, func(t *testing.T) {
			bp := parsePolicyLists(t, "blacklist "+entry)
			ts := newTestTurnstile(t)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
			req.TLS.HandshakeComplete = true
			if entry == "ua:BadBot" {
				req.Header.Set("User-Agent", "BadBot/1.0")
			}
			req.AddCookie(&http.Cookie{Name: ts.cookieName(), Value: ts.mintClearance(ts.now(), req)})
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
		for _, value := range []string{"not-an-ip", "203.0.113.0/33", "2001:db8::/129", "ua:[", "ua:"} {
			t.Run(directive+"/"+value, func(t *testing.T) {
				var bp BotPolicy
				if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n" + directive + " " + value + "\n}")); err != nil {
					t.Fatal(err)
				}
				if err := bp.Provision(caddy.Context{}); err == nil {
					t.Fatal("accepted invalid IP, CIDR or User-Agent pattern")
				}
			})
		}
	}
}
