package botpolicy

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
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

func parseASNMatcher(t *testing.T, db string, asns ...uint32) *MatchASN {
	t.Helper()
	m := &MatchASN{ASNDB: db, ASNs: asns}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func asnMatches(t *testing.T, m *MatchASN, ip string) bool {
	t.Helper()
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	req.TLS.HandshakeComplete = true
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, ip)
	match, err := m.MatchWithError(req)
	if err != nil {
		t.Fatal(err)
	}
	return match
}

func TestASNMatcherAddressesAndValidation(t *testing.T) {
	db := testASNDatabase(t, "GeoLite2-ASN")
	m := parseASNMatcher(t, db, 13335, 64500)
	for ip, want := range map[string]bool{
		"203.0.113.7":        true,
		"2001:db8:abcd::7":   true,
		"::ffff:203.0.113.7": true,
		"198.51.100.7":       false,
		"2001:db8:eeee::1":   false,
	} {
		if got := asnMatches(t, m, ip); got != want {
			t.Errorf("IP %s: got %v want %v", ip, got, want)
		}
	}
	for _, asns := range [][]uint32{nil, {0}} {
		bad := &MatchASN{ASNDB: db, ASNs: asns}
		if err := bad.Provision(caddy.Context{}); err == nil {
			t.Fatal("accepted invalid ASN list")
		}
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing.mmdb"), testASNDatabase(t, "GeoLite2-City")} {
		bad := &MatchASN{ASNDB: path, ASNs: []uint32{13335}}
		if err := bad.Provision(caddy.Context{}); err == nil {
			t.Errorf("accepted database %q", path)
		}
	}
}

func TestASNMatcherRejectsUnverifiedIP(t *testing.T) {
	m := parseASNMatcher(t, testASNDatabase(t, "GeoLite2-ASN"), 13335)
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	req.TLS.HandshakeComplete = false
	matched, err := m.MatchWithError(req)
	var httpErr caddyhttp.HandlerError
	if matched || !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusTooEarly {
		t.Fatalf("got (%v, %v), want HTTP 425", matched, err)
	}
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
	bp := parseASNMatcher(t, path, 13335)
	if got := asnMatches(t, bp, "203.0.113.7"); !got {
		t.Fatalf("before refresh: got match %v, want true", got)
	}
	original := bp.asnDB.reader.Load()
	replaceASNDatabase(t, path, testASNDatabaseWithASN(t, "GeoLite2-ASN", 64500))
	if err := bp.asnDB.refresh(); err != nil {
		t.Fatal(err)
	}
	if bp.asnDB.reader.Load() == original {
		t.Fatal("did not replace ASN reader")
	}
	if got := asnMatches(t, bp, "203.0.113.7"); got {
		t.Fatalf("after refresh: got match %v, want false", got)
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
	if bp.asnDB.reader.Load() != valid || asnMatches(t, bp, "203.0.113.7") {
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
	first := parseASNMatcher(t, path, 13335)
	second := parseASNMatcher(t, path, 13335)
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
func TestASNPolicyDatabaseTypes(t *testing.T) {
	for _, tt := range []struct {
		dbType string
		accept bool
	}{
		{"GeoLite2-ASN", true},
		{"GeoIP2-ASN", true},
		{"DBIP-ASN-Lite (compat=GeoLite2-ASN)", true},
		{"GeoLite2-City", false},
		{"DBIP-ASN-Lite", false},
	} {
		t.Run(tt.dbType, func(t *testing.T) {
			bp := &MatchASN{
				ASNDB: testASNDatabase(t, tt.dbType),
				ASNs:  []uint32{13335},
			}
			err := bp.Provision(caddy.Context{})
			if (err == nil) != tt.accept {
				t.Fatalf("provision accepted=%v, want %v (error: %v)", err == nil, tt.accept, err)
			}
			if err != nil {
				return
			}
			t.Cleanup(func() {
				if err := bp.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
			req.TLS.HandshakeComplete = true
			caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
			matched, err := bp.MatchWithError(req)
			if err != nil || !matched {
				t.Fatalf("got match %v, error %v; want match", matched, err)
			}
		})
	}
}
