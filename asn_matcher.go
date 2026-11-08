package botpolicy

import (
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

// MatchASN matches the resolved Caddy client IP against ASN numbers in a
// GeoLite2-compatible database. ASN database configuration is shared across
// matcher instances, including hot reloads and managed MaxMind updates.
type MatchASN struct {
	ASNs    []uint32    `json:"asns"`
	ASNDB   string      `json:"asn_db,omitempty"`
	MaxMind *MaxMindASN `json:"maxmind,omitempty"`

	asnDB   *asnDatabase
	managed *managedASNDB
	cleaned *atomic.Bool
	logger  *zap.Logger
}

func (MatchASN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.matchers.asn", New: func() caddy.Module { return new(MatchASN) }}
}

func (m *MatchASN) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if len(m.ASNs) == 0 {
		return fmt.Errorf("asn: at least one ASN is required")
	}
	for _, asn := range m.ASNs {
		if asn == 0 {
			return fmt.Errorf("asn: ASN must be between 1 and 4294967295")
		}
	}
	if m.MaxMind != nil && m.ASNDB != "" {
		return fmt.Errorf("asn: choose either a local asn_db or maxmind")
	}
	if m.MaxMind != nil {
		repl := caddy.NewReplacer()
		cfg := MaxMindASN{
			AccountID:  repl.ReplaceKnown(m.MaxMind.AccountID, ""),
			LicenseKey: repl.ReplaceKnown(m.MaxMind.LicenseKey, ""),
		}
		if cfg.AccountID == "" || cfg.LicenseKey == "" {
			return fmt.Errorf("asn: maxmind account_id and license_key are required")
		}
		var err error
		m.managed, err = acquireMaxMindDB(maxMindCachePath(), m, cfg, m.logger)
		if err != nil {
			return fmt.Errorf("asn: %w", err)
		}
	} else {
		if m.ASNDB == "" {
			return fmt.Errorf("asn: asn_db is required")
		}
		path, err := filepath.Abs(m.ASNDB)
		if err != nil {
			return fmt.Errorf("asn: resolve asn_db %q: %w", m.ASNDB, err)
		}
		value, _, err := asnDatabases.LoadOrNew(path, func() (caddy.Destructor, error) {
			return newASNDatabase(path, m.logger)
		})
		if err != nil {
			return err
		}
		m.asnDB = value.(*asnDatabase)
	}
	m.cleaned = new(atomic.Bool)
	return nil
}

func (m *MatchASN) Cleanup() error {
	if m.cleaned == nil || !m.cleaned.CompareAndSwap(false, true) {
		return nil
	}
	if m.managed != nil {
		m.managed.removeUser(m)
		_, err := maxMindDatabases.Delete(m.managed.path)
		return err
	}
	if m.asnDB != nil {
		_, err := asnDatabases.Delete(m.asnDB.path)
		return err
	}
	return nil
}

func (m *MatchASN) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

func (m *MatchASN) MatchWithError(r *http.Request) (bool, error) {
	// The resolved client IP cannot be trusted before the TLS handshake
	// finishes. Returning an error (rather than false) also protects `not asn`.
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("asn: client IP not verified before TLS handshake completes"))
	}
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, fmt.Errorf("asn: unavailable client IP: %w", err)
	}
	var reader *maxminddb.Reader
	if m.managed != nil {
		reader = m.managed.reader.Load()
	} else if m.asnDB != nil {
		reader = m.asnDB.reader.Load()
	}
	if reader == nil {
		return false, fmt.Errorf("asn: database unavailable")
	}
	result := reader.Lookup(addr.Unmap())
	if err := result.Err(); err != nil {
		return false, fmt.Errorf("asn: lookup failed: %w", err)
	}
	if !result.Found() {
		return false, nil
	}
	var record struct {
		ASN uint32 `maxminddb:"autonomous_system_number"`
	}
	if err := result.Decode(&record); err != nil {
		return false, fmt.Errorf("asn: lookup failed: %w", err)
	}
	return slices.Contains(m.ASNs, record.ASN), nil
}

var (
	_ caddy.Provisioner                 = (*MatchASN)(nil)
	_ caddy.CleanerUpper                = (*MatchASN)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchASN)(nil)
)
