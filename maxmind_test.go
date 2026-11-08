package botpolicy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type maxMindFixture struct {
	mu       sync.Mutex
	modified time.Time
	archive  []byte
	broken   bool
	head     int
	get      int
}

func fixtureASNData(t *testing.T, asn uint32, databaseType string) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: databaseType, IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, prefix, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert(prefix, mmdbtype.Map{
		"autonomous_system_number": mmdbtype.Uint32(asn),
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := tree.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func fixtureArchive(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gzipWriter := gzip.NewWriter(&out)
	tarWriter := tar.NewWriter(gzipWriter)
	hdr := &tar.Header{Name: "GeoLite2-ASN_20261108/GeoLite2-ASN.mmdb", Mode: 0600, Size: int64(len(data))}
	if err := tarWriter.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func fixtureServer(t *testing.T, state *maxMindFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		if r.URL.Path == "/download" {
			id, key, ok := r.BasicAuth()
			if !ok || id != "12345" || key != "secret-license" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/archive", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path != "/archive" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", state.modified.UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			state.head++
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		state.get++
		if state.broken {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(state.archive)
	}))
}

func provisionManagedPolicy(t *testing.T) *BotPolicy {
	t.Helper()
	bp := &BotPolicy{
		Blacklist: []string{"asn:13335"},
		MaxMind:   &MaxMindASN{AccountID: "12345", LicenseKey: "secret-license"},
	}
	if err := bp.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bp.Cleanup() })
	return bp
}

func managedResponse(t *testing.T, bp *BotPolicy) int {
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

func TestMaxMindDownloadsRefreshesAndPreservesCache(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	first := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	state := &maxMindFixture{
		modified: first,
		archive:  fixtureArchive(t, fixtureASNData(t, 13335, "GeoLite2-ASN")),
	}
	server := fixtureServer(t, state)
	defer server.Close()
	maxMindDownloadURL = server.URL + "/download"
	defer func() { maxMindDownloadURL = maxMindASNURL }()

	bp := provisionManagedPolicy(t)
	if code := managedResponse(t, bp); code != http.StatusForbidden {
		t.Fatalf("initial ASN policy returned %d", code)
	}
	cachePath := maxMindCachePath()
	if !strings.HasPrefix(cachePath, caddy.AppDataDir()) {
		t.Fatalf("cache path %q is outside Caddy data dir", cachePath)
	}
	info, err := os.Stat(cachePath)
	if err != nil || !info.ModTime().Equal(first) {
		t.Fatalf("expected cached file dated %v: %v %v", first, info, err)
	}
	if err := bp.managed.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	gets := state.get
	state.mu.Unlock()
	if gets != 1 {
		t.Fatalf("unchanged build was downloaded %d times", gets)
	}

	oldReader := bp.managed.reader.Load()
	state.mu.Lock()
	state.modified = first.Add(24 * time.Hour)
	state.archive = fixtureArchive(t, fixtureASNData(t, 64500, "GeoLite2-ASN"))
	state.mu.Unlock()
	if err := bp.managed.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code := managedResponse(t, bp); code != http.StatusOK {
		t.Fatalf("new ASN policy returned %d", code)
	}
	if bp.managed.reader.Load() == oldReader {
		t.Fatal("new database did not replace old reader")
	}
	// The previous reader still works for a request already using it.
	result := oldReader.Lookup(netip.MustParseAddr("203.0.113.7"))
	var record struct {
		ASN uint32 `maxminddb:"autonomous_system_number"`
	}
	if err := result.Decode(&record); err != nil || record.ASN != 13335 {
		t.Fatalf("in-flight old reader: %d, %v", record.ASN, err)
	}

	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.modified = first.Add(48 * time.Hour)
	state.broken = true
	state.mu.Unlock()
	if err := bp.managed.refresh(context.Background()); err == nil {
		t.Fatal("failed refresh was accepted")
	}
	after, err := os.ReadFile(cachePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed refresh changed cache: %v", err)
	}
	if code := managedResponse(t, bp); code != http.StatusOK {
		t.Fatalf("failed refresh replaced in-memory database: %d", code)
	}
	state.mu.Lock()
	state.broken = false
	state.archive = fixtureArchive(t, fixtureASNData(t, 13335, "GeoLite2-City"))
	state.mu.Unlock()
	if err := bp.managed.refresh(context.Background()); err == nil {
		t.Fatal("wrong database type was accepted")
	}
	if data, err := os.ReadFile(cachePath); err != nil || !bytes.Equal(data, before) {
		t.Fatalf("invalid MMDB replaced cached data: %v", err)
	}
}

func TestMaxMindCacheReuseAndConfigGenerations(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	state := &maxMindFixture{
		modified: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC),
		archive:  fixtureArchive(t, fixtureASNData(t, 13335, "GeoLite2-ASN")),
	}
	server := fixtureServer(t, state)
	defer server.Close()
	maxMindDownloadURL = server.URL + "/download"
	defer func() { maxMindDownloadURL = maxMindASNURL }()

	a := provisionManagedPolicy(t)
	b := provisionManagedPolicy(t)
	if a.managed != b.managed {
		t.Fatal("config generations started separate refreshers")
	}
	if refs, ok := maxMindDatabases.References(maxMindCachePath()); !ok || refs != 2 {
		t.Fatalf("expected 2 pool references, got %d (ok: %v)", refs, ok)
	}
	if err := a.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if refs, ok := maxMindDatabases.References(maxMindCachePath()); !ok || refs != 1 {
		t.Fatalf("expected 1 pool reference, got %d (ok: %v)", refs, ok)
	}
	if err := b.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, ok := maxMindDatabases.References(maxMindCachePath()); ok {
		t.Fatal("refresher still pooled after last cleanup")
	}
	// A new configuration uses the disk cache without a startup GET, even
	// when the network check will fail in the background.
	state.mu.Lock()
	state.broken = true
	state.mu.Unlock()
	c := provisionManagedPolicy(t)
	if code := managedResponse(t, c); code != http.StatusForbidden {
		t.Fatalf("cached ASN policy returned %d", code)
	}
	state.mu.Lock()
	gets := state.get
	state.mu.Unlock()
	if gets != 1 {
		t.Fatalf("cached startup made %d downloads", gets)
	}
}

func TestMaxMindProvisionFailureWithoutCache(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	state := &maxMindFixture{modified: time.Now(), broken: true}
	server := fixtureServer(t, state)
	defer server.Close()
	maxMindDownloadURL = server.URL + "/download"
	defer func() { maxMindDownloadURL = maxMindASNURL }()

	bp := &BotPolicy{
		Blacklist: []string{"asn:13335"},
		MaxMind:   &MaxMindASN{AccountID: "12345", LicenseKey: "secret-license"},
	}
	err := bp.Provision(caddy.Context{})
	if err == nil || strings.Contains(err.Error(), "secret-license") {
		t.Fatalf("expected safe startup error, got %v", err)
	}
	if _, ok := maxMindDatabases.References(maxMindCachePath()); ok {
		t.Fatal("failed startup leaked refresher pool entry")
	}
	if _, err := os.Stat(maxMindCachePath()); !os.IsNotExist(err) {
		t.Fatalf("failed startup wrote a cache file: %v", err)
	}
}

func TestMaxMindCaddyfileAndCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		wantErr      bool
	}{
		{"managed", "asn_db maxmind {\naccount_id {env.MAXMIND_ACCOUNT_ID}\nlicense_key {env.MAXMIND_LICENSE_KEY}\n}", false},
		{"local", "asn_db /data/asn.mmdb", false},
		{"missing account", "asn_db maxmind {\nlicense_key secret\n}", true},
		{"missing license", "asn_db maxmind {\naccount_id 12345\n}", true},
		{"unknown option", "asn_db maxmind {\nusername foo\naccount_id x\nlicense_key y\n}", true},
		{"duplicate", "asn_db /data/asn.mmdb\nasn_db maxmind {\naccount_id x\nlicense_key y\n}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bp BotPolicy
			err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser("bot_policy {\n" + tc.config + "\nblacklist asn:13335\n}"))
			if (err != nil) != tc.wantErr {
				t.Fatalf("parse error: %v, want error %v", err, tc.wantErr)
			}
			if err == nil && tc.name == "managed" && (bp.MaxMind == nil || bp.MaxMind.AccountID != "{env.MAXMIND_ACCOUNT_ID}") {
				t.Fatalf("bad parsed MaxMind credentials: %#v", bp.MaxMind)
			}
		})
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("MAXMIND_ACCOUNT_ID", "12345")
	t.Setenv("MAXMIND_LICENSE_KEY", "secret-license")
	data := fixtureASNData(t, 13335, "GeoLite2-ASN")
	state := &maxMindFixture{modified: time.Now(), archive: fixtureArchive(t, data)}
	server := fixtureServer(t, state)
	defer server.Close()
	maxMindDownloadURL = server.URL + "/download"
	defer func() { maxMindDownloadURL = maxMindASNURL }()
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(caddyfile.NewTestDispenser(
		"bot_policy {\nasn_db maxmind {\naccount_id {env.MAXMIND_ACCOUNT_ID}\nlicense_key {env.MAXMIND_LICENSE_KEY}\n}\nblacklist asn:13335\n}")); err != nil {
		t.Fatal(err)
	}
	if err := bp.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	defer bp.Cleanup()
	if code := managedResponse(t, &bp); code != http.StatusForbidden {
		t.Fatalf("placeholder credentials did not download database: %d", code)
	}
	if _, err := os.Stat(filepath.Join(caddy.AppDataDir(), "bot_policy", "GeoLite2-ASN.mmdb")); err != nil {
		t.Fatal(err)
	}
}
