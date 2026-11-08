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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"go.uber.org/zap"
)

func testASNDatabase(t *testing.T, dbType string) string {
	return testASNDatabaseWithASN(t, dbType, 13335)
}

func testASNDatabaseWithASN(t *testing.T, dbType string, ipv4ASN uint32) string {
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
		{"203.0.113.0/24", ipv4ASN},
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
		name, rules, ip, agent string
		status                 int
		challenge              bool
	}{
		{"IPv4 ASN blacklist", "blacklist asn:13335", "203.0.113.7", "", 403, false},
		{"IPv6 ASN blacklist", "blacklist asn:64500", "2001:db8:abcd::7", "", 403, false},
		{"IPv4-mapped IPv6", "blacklist asn:13335", "::ffff:203.0.113.7", "", 403, false},
		{"ASN whitelist bypasses Turnstile", "whitelist asn:13335", "203.0.113.7", "", 200, false},
		{"ASN blacklist defeats IP whitelist", "whitelist 203.0.113.7\nblacklist asn:13335", "203.0.113.7", "", 403, false},
		{"ASN blacklist defeats UA whitelist", "whitelist ua:GoodBot\nblacklist asn:13335", "203.0.113.7", "GoodBot", 403, false},
		{"IP blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist 203.0.113.0/24", "203.0.113.7", "", 403, false},
		{"UA blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist ua:BadBot", "203.0.113.7", "BadBot", 403, false},
		{"ASN blacklist defeats ASN whitelist", "whitelist asn:13335\nblacklist asn:13335", "203.0.113.7", "", 403, false},
		{"unmatched ASN gets Turnstile", "blacklist asn:13335", "198.51.100.7", "", 403, true},
		{"unmapped IPv6", "blacklist asn:64500", "2001:db8:eeee::1", "", 403, true},
		{"other ASN is not a match", "blacklist asn:64500", "203.0.113.7", "", 403, true},
		{"mixed list types", "whitelist 198.51.100.7 ua:GoodBot asn:13335", "203.0.113.7", "", 200, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bp := parseASNPolicy(t, db, tt.rules)
			ts := newTestTurnstile(t)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
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
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
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
	ts := newTestTurnstile(t)
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req.TLS.HandshakeComplete = true
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	req.AddCookie(&http.Cookie{Name: ts.cookieName(), Value: ts.mintClearance(ts.now(), req)})
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
	for _, tt := range []struct {
		name, rules, agent string
		status             int
	}{
		{"ASN-only whitelist needs verified IP", "whitelist asn:13335", "", 425},
		{"UA whitelist can bypass without ASN blacklist", "whitelist asn:13335 ua:GoodBot", "GoodBot", 200},
		{"ASN blacklist prevents premature UA bypass", "blacklist asn:13335\nwhitelist ua:GoodBot", "GoodBot", 425},
		{"UA blacklist still blocks", "blacklist asn:13335 ua:BadBot", "BadBot", 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bp := parseASNPolicy(t, db, tt.rules)
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
			req.Header.Set("User-Agent", tt.agent)
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
			// An early-data request cannot establish its source IP securely.
			req.TLS.HandshakeComplete = false
			rec := httptest.NewRecorder()
			err := bp.ServeHTTP(rec, req, passThrough)
			if tt.status == 425 {
				var httpErr caddyhttp.HandlerError
				if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooEarly {
					t.Fatalf("got %v, want HTTP 425", err)
				}
			} else if err != nil || rec.Code != tt.status {
				t.Fatalf("got status %d, error %v, want %d", rec.Code, err, tt.status)
			}
		})
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

func asnPolicyStatus(t *testing.T, bp *BotPolicy) int {
	t.Helper()
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req.TLS.HandshakeComplete = true
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	rec := httptest.NewRecorder()
	if err := bp.ServeHTTP(rec, req, passThrough); err != nil {
		t.Fatal(err)
	}
	return rec.Code
}

func replaceASNDatabase(t *testing.T, destination, source string) {
	t.Helper()
	// An explicit timestamp change makes the stat-based test reliable.
	when := time.Now().Add(time.Hour)
	if err := os.Chtimes(source, when, when); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, destination); err != nil {
		t.Fatal(err)
	}
}

func TestASNPolicyRefreshesAndRetainsLastValidDatabase(t *testing.T) {
	path := testASNDatabase(t, "GeoLite2-ASN")
	bp := parseASNPolicy(t, path, "blacklist asn:13335")
	if got := asnPolicyStatus(t, bp); got != http.StatusForbidden {
		t.Fatalf("before refresh: got %d, want 403", got)
	}
	original := bp.asnDB.reader.Load()
	replaceASNDatabase(t, path, testASNDatabaseWithASN(t, "GeoLite2-ASN", 64500))
	if err := bp.asnDB.refresh(); err != nil {
		t.Fatal(err)
	}
	if bp.asnDB.reader.Load() == original {
		t.Fatal("did not replace ASN reader")
	}
	if got := asnPolicyStatus(t, bp); got != http.StatusOK {
		t.Fatalf("after refresh: got %d, want 200", got)
	}

	valid := bp.asnDB.reader.Load()
	invalid := filepath.Join(t.TempDir(), "invalid.mmdb")
	if err := os.WriteFile(invalid, []byte("not an MMDB"), 0600); err != nil {
		t.Fatal(err)
	}
	replaceASNDatabase(t, path, invalid)
	if err := bp.asnDB.refresh(); err == nil {
		t.Fatal("accepted a corrupt replacement database")
	}
	if bp.asnDB.reader.Load() != valid || asnPolicyStatus(t, bp) != http.StatusOK {
		t.Fatal("corrupt replacement displaced last valid database")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := bp.asnDB.refresh(); err == nil || bp.asnDB.reader.Load() != valid {
		t.Fatalf("missing database displaced last valid reader: %v", err)
	}
}

func TestASNPolicySharesWatcherPerPath(t *testing.T) {
	path := testASNDatabase(t, "GeoLite2-ASN")
	first := parseASNPolicy(t, path, "blacklist asn:13335")
	second := parseASNPolicy(t, path, "whitelist asn:13335")
	if first.asnDB != second.asnDB {
		t.Fatal("expected handlers to share the same database watcher")
	}
	if refs, ok := asnDatabases.References(first.asnDB.path); !ok || refs != 2 {
		t.Fatalf("expected two watcher references, got %d, present=%v", refs, ok)
	}
}

func TestASNDatabaseWatcherRefreshesFile(t *testing.T) {
	path := testASNDatabase(t, "GeoLite2-ASN")
	db := &asnDatabase{
		path:   path,
		logger: zap.NewNop(),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	if err := db.refresh(); err != nil {
		t.Fatal(err)
	}
	previous := db.reader.Load()
	go db.watch(5 * time.Millisecond)
	t.Cleanup(func() {
		if err := db.Destruct(); err != nil {
			t.Error(err)
		}
	})

	replaceASNDatabase(t, path, testASNDatabaseWithASN(t, "GeoLite2-ASN", 64500))
	deadline := time.Now().Add(2 * time.Second)
	for db.reader.Load() == previous && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if db.reader.Load() == previous {
		t.Fatal("watcher did not detect database replacement")
	}
}
