package botpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

// BotPolicy applies whitelists and blacklists to client IPs,
// User-Agent headers and ASNs.
type BotPolicy struct {
	// Whitelist contains IPs, CIDRs, ua:-prefixed regular expressions
	// and asn:-prefixed AS numbers. A match bypasses Turnstile unless
	// the blacklist also matches. IPs use Caddy client IP resolution.
	Whitelist []string `json:"whitelist,omitempty"`

	// Blacklist accepts the same entries as Whitelist. Any match receives
	// a 403, regardless of other whitelist matches or Turnstile clearance.
	// Blacklist always wins, regardless of prefix length or entry order.
	// Both lists are validated when the configuration is provisioned.
	Blacklist []string `json:"blacklist,omitempty"`

	// ASNDB is a local GeoLite2-ASN or GeoIP2-ASN MMDB path. Alternatively,
	// configure MaxMind to download and refresh GeoLite2-ASN automatically.
	// One of these is required if either policy list contains an asn: entry.
	ASNDB   string      `json:"asn_db,omitempty"`
	MaxMind *MaxMindASN `json:"maxmind,omitempty"`

	// Action is the response taken when a request is blocked. Only
	// "block-403" is currently supported: responds 403 and attaches a
	// unique block ID for tracing/support.
	Action string `json:"action,omitempty"`

	whitelist policyList
	blacklist policyList
	asnReader *maxminddb.Reader
	managed   *managedASNDB
	logger    *zap.Logger
}

// A private context key carries whitelist matches to downstream Turnstile
// handlers without making a request variable an authorization decision.
type policyWhitelistKey struct{}

type policyList struct {
	ips        caddyhttp.MatchClientIP
	userAgents []*regexp.Regexp
	asns       map[uint32]bool
}

func (list *policyList) provision(ctx caddy.Context, entries []string) error {
	list.ips = caddyhttp.MatchClientIP{}
	list.userAgents = nil
	list.asns = make(map[uint32]bool)
	for _, entry := range entries {
		if number, ok := strings.CutPrefix(entry, "asn:"); ok {
			if number == "" || strings.IndexFunc(number, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return fmt.Errorf("invalid ASN %q", entry)
			}
			asn, err := strconv.ParseUint(number, 10, 32)
			if err != nil || asn == 0 {
				return fmt.Errorf("invalid ASN %q (must be between 1 and 4294967295)", entry)
			}
			list.asns[uint32(asn)] = true
		} else if pattern, ok := strings.CutPrefix(entry, "ua:"); ok {
			if pattern == "" {
				return fmt.Errorf("empty User-Agent pattern %q", entry)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid User-Agent pattern %q: %w", entry, err)
			}
			list.userAgents = append(list.userAgents, re)
		} else {
			list.ips.Ranges = append(list.ips.Ranges, entry)
		}
	}
	return list.ips.Provision(ctx)
}

func (list policyList) match(r *http.Request, asn uint32) (bool, error) {
	if asn != 0 && list.asns[asn] {
		return true, nil
	}
	if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
		for _, re := range list.userAgents {
			if re.MatchString(userAgent) {
				return true, nil
			}
		}
	}
	if len(list.ips.Ranges) == 0 {
		return false, nil
	}
	return list.ips.MatchWithError(r)
}

// CaddyModule returns the Caddy module information.
func (BotPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.bot_policy",
		New: func() caddy.Module { return new(BotPolicy) },
	}
}

// Provision validates and indexes the policy lists.
func (bp *BotPolicy) Provision(ctx caddy.Context) error {
	bp.logger = ctx.Logger()

	if bp.Action == "" {
		bp.Action = "block-403"
	}
	switch bp.Action {
	case "block-403":
	default:
		return fmt.Errorf("bot_policy: unsupported action %q (only 'block-403' is implemented)", bp.Action)
	}

	if err := bp.whitelist.provision(ctx, bp.Whitelist); err != nil {
		return fmt.Errorf("bot_policy: whitelist: %w", err)
	}
	if err := bp.blacklist.provision(ctx, bp.Blacklist); err != nil {
		return fmt.Errorf("bot_policy: blacklist: %w", err)
	}
	if err := bp.Validate(); err != nil {
		return err
	}
	if len(bp.whitelist.asns) > 0 || len(bp.blacklist.asns) > 0 {
		if bp.MaxMind != nil && bp.ASNDB != "" {
			return fmt.Errorf("bot_policy: choose either a local asn_db or maxmind")
		}
		if bp.MaxMind != nil {
			repl := caddy.NewReplacer()
			cfg := MaxMindASN{
				AccountID:  repl.ReplaceKnown(bp.MaxMind.AccountID, ""),
				LicenseKey: repl.ReplaceKnown(bp.MaxMind.LicenseKey, ""),
			}
			if cfg.AccountID == "" || cfg.LicenseKey == "" {
				return fmt.Errorf("bot_policy: maxmind account_id and license_key are required")
			}
			var err error
			bp.managed, err = acquireMaxMindDB(maxMindCachePath(), cfg, bp.logger)
			if err != nil {
				return fmt.Errorf("bot_policy: %w", err)
			}
		} else {
			if bp.ASNDB == "" {
				return fmt.Errorf("bot_policy: asn_db is required for ASN rules")
			}
			data, err := os.ReadFile(bp.ASNDB)
			if err != nil {
				return fmt.Errorf("bot_policy: read asn_db %q: %w", bp.ASNDB, err)
			}
			// In-flight requests on an old config keep their in-memory reader.
			reader, err := openASNDatabase(data, false)
			if err != nil {
				return fmt.Errorf("bot_policy: open asn_db %q: %w", bp.ASNDB, err)
			}
			bp.asnReader = reader
		}
	}
	return nil
}

// Cleanup releases this config's use of the shared MaxMind refresher.
func (bp *BotPolicy) Cleanup() error {
	if bp.managed == nil {
		return nil
	}
	_, err := maxMindDatabases.Delete(bp.managed.path)
	bp.managed = nil
	return err
}

// Validate ensures bp has at least one policy entry.
func (bp *BotPolicy) Validate() error {
	if len(bp.Whitelist) == 0 && len(bp.Blacklist) == 0 {
		return fmt.Errorf("bot_policy: at least one 'whitelist' or 'blacklist' entry is required")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (bp *BotPolicy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	reader := bp.asnReader
	if bp.managed != nil {
		reader = bp.managed.reader.Load()
	}
	// In 0-RTT, the source IP is not yet verified. A known blacklist
	// match can still block, and a non-IP whitelist can still bypass
	// when there are no unresolved ASN blacklist rules.
	early := reader != nil && r.TLS != nil && !r.TLS.HandshakeComplete
	var asn uint32
	if reader != nil && !early {
		ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
		if addr, err := netip.ParseAddr(ip); err == nil {
			result := reader.Lookup(addr.Unmap())
			var record struct {
				ASN uint32 `maxminddb:"autonomous_system_number"`
			}
			if err := result.Err(); err != nil {
				bp.logger.Error("ASN lookup failed", zap.Error(err))
			} else if result.Found() {
				if err := result.Decode(&record); err != nil {
					bp.logger.Error("ASN lookup failed", zap.Error(err))
				} else {
					asn = record.ASN
				}
			}
		}
	}
	blacklisted, err := bp.blacklist.match(r, asn)
	if err != nil {
		return err
	}
	if blacklisted {
		return bp.block(w, r)
	}
	if early && len(bp.blacklist.asns) > 0 {
		return caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}
	whitelisted, err := bp.whitelist.match(r, asn)
	if err != nil {
		return err
	}
	if whitelisted {
		r = r.WithContext(context.WithValue(r.Context(), policyWhitelistKey{}, true))
		return next.ServeHTTP(w, r)
	}
	if early {
		return caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}
	return next.ServeHTTP(w, r)
}

func (bp *BotPolicy) block(w http.ResponseWriter, r *http.Request) error {
	id := newBlockID("bp-")

	bp.logger.Info("blocked request",
		zap.String("block_id", id),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
		zap.String("uri", r.RequestURI),
	)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Block-Id", id)
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "403 Forbidden (block id: %s)\n", id)
	return nil
}

// newBlockID returns a random ID, with a prefix naming the handler that
// blocked the request, for matching a user's report to a log line.
func newBlockID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*BotPolicy)(nil)
	_ caddy.CleanerUpper          = (*BotPolicy)(nil)
	_ caddy.Validator             = (*BotPolicy)(nil)
	_ caddyhttp.MiddlewareHandler = (*BotPolicy)(nil)
)
