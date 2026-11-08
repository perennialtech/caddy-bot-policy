package botpolicy

import (
	"net/http"
	"strings"
	"testing"
)

func TestIntegrationPolicyClientIP(t *testing.T) {
	for _, tt := range []struct {
		name, rules, forwarded string
		trusted                bool
		status                 int
		challenge              bool
	}{
		{"direct client", "whitelist 127.0.0.1", "", false, 200, false},
		{"untrusted whitelist header", "whitelist 203.0.113.0/24", "203.0.113.7", false, 403, true},
		{"trusted whitelist header", "whitelist 203.0.113.0/24", "203.0.113.7", true, 200, false},
		{"untrusted blacklist header", "blacklist 203.0.113.0/24", "203.0.113.7", false, 403, true},
		{"trusted blacklist header", "blacklist 203.0.113.0/24", "203.0.113.7", true, 403, false},
		{"resolved IP overrides socket IP", "whitelist 127.0.0.1\nblacklist 203.0.113.0/24", "203.0.113.7", true, 403, false},
		{"trusted IPv6 header", "whitelist 2001:db8::/32", "2001:db8:1::7", true, 200, false},
		{"strict proxy chain", "whitelist 203.0.113.0/24", "203.0.113.7, 198.51.100.7, 127.0.0.1", true, 403, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			globals := ""
			if tt.trusted {
				globals = "servers {\ntrusted_proxies static 127.0.0.1/32\ntrusted_proxies_strict\n}"
			}
			base := startCaddy(t, "bot_policy {\n"+tt.rules+"\n}\n%TURNSTILE%\nrespond protected", globals)
			req, err := http.NewRequest(http.MethodGet, base+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			resp, body := newVisitor(t, base).do(req)
			if resp.StatusCode != tt.status || strings.Contains(body, "cf-turnstile") != tt.challenge {
				t.Fatalf("got %d %q, want %d, challenge %v", resp.StatusCode, body, tt.status, tt.challenge)
			}
			if tt.status == 200 && body != "protected" {
				t.Fatalf("whitelist did not reach downstream handler: %q", body)
			}
			if tt.status == 403 && !tt.challenge && !strings.HasPrefix(resp.Header.Get("X-Block-Id"), "bp-") {
				t.Fatalf("expected bot_policy block, got %v", resp.Header)
			}
		})
	}
}

func TestIntegrationASNClientIP(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	for _, tt := range []struct {
		name, rules, forwarded string
		trusted                bool
		status                 int
		challenge              bool
	}{
		{"untrusted ASN whitelist header", "whitelist asn:13335", "203.0.113.7", false, 403, true},
		{"trusted ASN whitelist header", "whitelist asn:13335", "203.0.113.7", true, 200, false},
		{"untrusted ASN blacklist header", "blacklist asn:13335", "203.0.113.7", false, 403, true},
		{"trusted ASN blacklist header", "blacklist asn:13335", "203.0.113.7", true, 403, false},
		{"trusted IPv6 ASN header", "whitelist asn:64500", "2001:db8:abcd::7", true, 200, false},
		{"strict proxy chain", "whitelist asn:13335", "203.0.113.7, 198.51.100.7, 127.0.0.1", true, 403, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			globals := ""
			if tt.trusted {
				globals = "servers {\ntrusted_proxies static 127.0.0.1/32\ntrusted_proxies_strict\n}"
			}
			base := startCaddy(t, "bot_policy {\nasn_db "+db+"\n"+tt.rules+"\n}\n%TURNSTILE%\nrespond protected", globals)
			req, err := http.NewRequest(http.MethodGet, base+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			req.Header.Set("X-ASN", "13335")
			resp, body := newVisitor(t, base).do(req)
			if resp.StatusCode != tt.status || strings.Contains(body, "cf-turnstile") != tt.challenge {
				t.Fatalf("got %d %q, want status %d, challenge %v", resp.StatusCode, body, tt.status, tt.challenge)
			}
		})
	}
}
