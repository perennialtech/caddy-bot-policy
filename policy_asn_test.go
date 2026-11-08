package botpolicy

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func testASNDatabase(t *testing.T, dbType string) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            dbType,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range []struct {
		cidr string
		asn  uint32
	}{
		{"203.0.113.0/24", 13335},
		{"2001:db8:abcd::/48", 64500},
	} {
		_, network, err := net.ParseCIDR(mapping.cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Insert(network, mmdbtype.Map{
			"autonomous_system_number": mmdbtype.Uint32(mapping.asn),
		}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.WriteTo(f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func parseASNPolicy(t *testing.T, db, rules string) *BotPolicy {
	t.Helper()
	var bp BotPolicy
	d := caddyfile.NewTestDispenser("bot_policy {\nasn_db " + db + "\n" + rules + "\n}")
	if err := bp.UnmarshalCaddyfile(d); err != nil {
		t.Fatal(err)
	}
	if err := bp.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bp.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return &bp
}

func TestASNPolicyRules(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	for _, tt := range []struct {
		name, rules, ip, fingerprint, agent string
		status                              int
		challenge                           bool
	}{
		{"IPv4 ASN blacklist", "blacklist asn:13335", "203.0.113.7", "", "", 403, false},
		{"IPv6 ASN blacklist", "blacklist asn:64500", "2001:db8:abcd::7", "", "", 403, false},
		{"IPv4-mapped IPv6", "blacklist asn:13335", "::ffff:203.0.113.7", "", "", 403, false},
		{"ASN whitelist bypasses Turnstile", "whitelist asn:13335", "203.0.113.7", testFP, "", 200, false},
		{"ASN whitelist without JA4", "whitelist asn:13335\non_missing_fingerprint closed", "203.0.113.7", "", "", 200, false},
		{"ASN blacklist defeats IP whitelist", "whitelist 203.0.113.7\nblacklist asn:13335", "203.0.113.7", testFP, "", 403, false},
		{"ASN blacklist defeats JA4 whitelist", "whitelist " + testFP + "\nblacklist asn:13335", "203.0.113.7", testFP, "", 403, false},
		{"ASN blacklist defeats UA whitelist", "whitelist ua:GoodBot\nblacklist asn:13335", "203.0.113.7", "", "GoodBot", 403, false},
		{"IP blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist 203.0.113.0/24", "203.0.113.7", testFP, "", 403, false},
		{"JA4 blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist " + testFP, "203.0.113.7", testFP, "", 403, false},
		{"UA blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist ua:BadBot", "203.0.113.7", "", "BadBot", 403, false},
		{"ASN blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist asn:13335", "203.0.113.7", testFP, "", 403, false},
		{"unmatched ASN gets Turnstile", "blacklist asn:13335", "198.51.100.7", testFP, "", 403, true},
		{"unmatched ASN preserves missing-fingerprint closed", "whitelist asn:13335\non_missing_fingerprint closed", "198.51.100.7", "", "", 403, false},
		{"unmapped IPv6", "blacklist asn:64500", "2001:db8:eeee::1", testFP, "", 403, true},
		{"other ASN is not a match", "blacklist asn:64500", "203.0.113.7", testFP, "", 403, true},
		{"mixed list types", "whitelist 198.51.100.7 ua:GoodBot asn:13335 " + testFP, "203.0.113.7", "", "", 200, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bp := parseASNPolicy(t, db, tt.rules)
			ts := newTestTurnstile(t, true)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", tt.fingerprint, nil)
			req.TLS.HandshakeComplete = true
			req.Header.Set("User-Agent", tt.agent)
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

func TestASNPolicyUsesCaddyClientIP(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	bp := parseASNPolicy(t, db, "blacklist asn:13335")

	for _, tt := range []struct {
		name, resolvedIP string
		status           int
	}{
		{"untrusted forwarding header", "198.51.100.7", 200},
		{"trusted proxy resolved client", "203.0.113.7", 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", "", nil)
			req.TLS.HandshakeComplete = true
			req.RemoteAddr = "198.51.100.7:1234"
			req.Header.Set("X-Forwarded-For", "203.0.113.7")
			req.Header.Set("X-ASN", "13335")
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, tt.resolvedIP)
			rec := httptest.NewRecorder()
			if err := bp.ServeHTTP(rec, req, passThrough); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tt.status {
				t.Fatalf("got %d, want %d", rec.Code, tt.status)
			}
		})
	}
}

func TestASNBlacklistOverridesTurnstileClearance(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	bp := parseASNPolicy(t, db, "blacklist asn:13335")
	ts := newTestTurnstile(t, true)
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", testFP, nil)
	req.TLS.HandshakeComplete = true
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	req.AddCookie(&http.Cookie{Name: ts.cookieName(testFP, true), Value: ts.mintClearance(ts.now(), req)})
	if !ts.cleared(req) {
		t.Fatal("test clearance must be valid")
	}
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ts.ServeHTTP(w, r, passThrough)
	})
	if err := bp.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden || !strings.HasPrefix(rec.Header().Get("X-Block-Id"), "bp-") {
		t.Fatalf("clearance bypassed ASN blacklist: status %d, headers %v", rec.Code, rec.Header())
	}
}

func TestASNPolicyRejectsUnverifiedClientIP(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	bp := parseASNPolicy(t, db, "whitelist asn:13335")
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", "", nil)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	// An early-data request cannot establish the source address securely.
	req.TLS.HandshakeComplete = false
	err := bp.ServeHTTP(httptest.NewRecorder(), req, passThrough)
	var httpErr caddyhttp.HandlerError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooEarly {
		t.Fatalf("unverified source: got %v, want HTTP 425", err)
	}
}

func TestASNPolicyValidation(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	for _, directive := range []string{"whitelist", "blacklist"} {
		for _, badASN := range []string{"asn:", "asn:0", "asn:-1", "asn:+1", "asn:abc", "asn:1.5", "asn:4294967296"} {
			t.Run(directive+"/"+badASN, func(t *testing.T) {
				var bp BotPolicy
				bp.ASNDB = db
				if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n" + directive + " " + badASN + "\n}")); err != nil {
					t.Fatal(err)
				}
				if err := bp.Provision(caddy.Context{}); err == nil {
					t.Fatal("accepted invalid ASN")
				}
			})
		}
	}
	for _, tt := range []struct {
		name, db string
	}{
		{"missing database option", ""},
		{"missing file", filepath.Join(t.TempDir(), "missing.mmdb")},
		{"wrong database type", testASNDatabase(t, "GeoLite2-City")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var bp BotPolicy
			bp.ASNDB = tt.db
			bp.Blacklist = []string{"asn:13335"}
			if err := bp.Provision(caddy.Context{}); err == nil {
				t.Fatal("accepted an unavailable ASN database")
			}
		})
	}
}
