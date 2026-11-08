package botpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

// BotPolicy applies whitelists and blacklists to client IP addresses,
// TLS client fingerprints (JA4), User-Agent headers, and ASNs. Fingerprints come
// from the ja4 handler, which needs the ja4 listener or packet conn wrapper
// to have captured the ClientHello.
type BotPolicy struct {
	// VarName names the fingerprint to match: the ja4 handler's var_name or
	// bind_var_name. It is read from the ja4 handler directly, not from the
	// request variable, which other directives can overwrite. Defaults to
	// "ja4".
	VarName string `json:"var_name,omitempty"`

	// Whitelist contains JA4 identifiers, IPv4/IPv6 addresses and CIDRs,
	// ua:-prefixed Go regular expressions, and asn:-prefixed AS numbers.
	// Any match bypasses on_missing_fingerprint closed and downstream
	// Turnstile challenges, unless Blacklist also matches.
	// IP and ASN matching use Caddy's resolved client IP, respecting trusted_proxies.
	// At least one entry in Whitelist or Blacklist is required.
	Whitelist []string `json:"whitelist,omitempty"`

	// Blacklist accepts the same entries as Whitelist. Any match receives
	// a 403, regardless of other whitelist matches or Turnstile clearance.
	// Blacklist always wins, regardless of prefix length or entry order.
	// Both lists are validated when the configuration is provisioned.
	Blacklist []string `json:"blacklist,omitempty"`

	// ASNDB is the local path to a MaxMind GeoLite2-ASN or GeoIP2-ASN MMDB.
	// It is required when either policy list has an asn: entry. An unreadable
	// or incompatible database rejects the configuration at startup.
	ASNDB string `json:"asn_db,omitempty"`

	// OnMissingFingerprint is "open" (let the request through when the ja4
	// handler published no fingerprint under var_name) or "closed" (block
	// it). Defaults to "open". All lists are evaluated before this policy,
	// including ASN and User-Agent rules when the fingerprint is missing.
	OnMissingFingerprint string `json:"on_missing_fingerprint,omitempty"`

	// Action is the response taken when a request is blocked. Only
	// "block-403" is currently supported: responds 403 and attaches a
	// unique block ID for tracing/support.
	Action string `json:"action,omitempty"`

	whitelist policyList
	blacklist policyList
	asnReader *maxminddb.Reader
	logger    *zap.Logger
}

// A private context key carries whitelist matches to downstream Turnstile
// handlers without making a request variable an authorization decision.
type policyWhitelistKey struct{}

type policyList struct {
	fingerprints map[string]bool
	ips          caddyhttp.MatchClientIP
	userAgents   []*regexp.Regexp
	asns         map[uint32]bool
}

// Matches the fixed-width identifiers produced by clientHello.ja4,
// including the uppercase ALPN characters permitted by alpnCode.
var ja4Identifier = regexp.MustCompile(`^[tq]([0-9]{2}|s[123])[di][0-9]{4}[a-zA-Z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func (list *policyList) provision(ctx caddy.Context, entries []string) error {
	list.fingerprints = make(map[string]bool)
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
		} else if ja4Identifier.MatchString(entry) {
			list.fingerprints[entry] = true
		} else {
			list.ips.Ranges = append(list.ips.Ranges, entry)
		}
	}
	return list.ips.Provision(ctx)
}

func (list policyList) match(r *http.Request, fingerprint string, asn uint32) (bool, error) {
	if list.fingerprints[fingerprint] {
		return true, nil
	}
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

// Provision validates the lists and indexes the fingerprints for O(1) lookup.
func (bp *BotPolicy) Provision(ctx caddy.Context) error {
	bp.logger = ctx.Logger()

	if bp.VarName == "" {
		bp.VarName = defaultVarName
	}

	if bp.OnMissingFingerprint == "" {
		bp.OnMissingFingerprint = "open"
	}
	switch bp.OnMissingFingerprint {
	case "open", "closed":
	default:
		return fmt.Errorf("bot_policy: on_missing_fingerprint must be 'open' or 'closed', got %q", bp.OnMissingFingerprint)
	}

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
		if bp.ASNDB == "" {
			return fmt.Errorf("bot_policy: asn_db is required for ASN rules")
		}
		reader, err := maxminddb.Open(bp.ASNDB)
		if err != nil {
			return fmt.Errorf("bot_policy: open asn_db %q: %w", bp.ASNDB, err)
		}
		if reader.Metadata.DatabaseType != "GeoLite2-ASN" && reader.Metadata.DatabaseType != "GeoIP2-ASN" {
			reader.Close()
			return fmt.Errorf("bot_policy: asn_db %q is not a MaxMind ASN database", bp.ASNDB)
		}
		bp.asnReader = reader
	}
	return nil
}

// Cleanup releases the memory-mapped ASN database when Caddy unloads the module.
func (bp *BotPolicy) Cleanup() error {
	if bp.asnReader != nil {
		return bp.asnReader.Close()
	}
	return nil
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
	fingerprint := trustedFingerprint(r, bp.VarName)
	var asn uint32
	if bp.asnReader != nil {
		// MatchClientIP likewise refuses an unverified 0-RTT source address.
		if r.TLS != nil && !r.TLS.HandshakeComplete {
			return caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
		}
		ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
		if addr, err := netip.ParseAddr(ip); err == nil {
			result := bp.asnReader.Lookup(addr.Unmap())
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
	blacklisted, err := bp.blacklist.match(r, fingerprint, asn)
	if err != nil {
		return err
	}
	if blacklisted {
		return bp.block(w, r, fingerprint)
	}
	whitelisted, err := bp.whitelist.match(r, fingerprint, asn)
	if err != nil {
		return err
	}
	if whitelisted {
		r = r.WithContext(context.WithValue(r.Context(), policyWhitelistKey{}, true))
		return next.ServeHTTP(w, r)
	}
	if fingerprint == "" && bp.OnMissingFingerprint == "closed" {
		return bp.block(w, r, fingerprint)
	}
	return next.ServeHTTP(w, r)
}

func (bp *BotPolicy) block(w http.ResponseWriter, r *http.Request, fingerprint string) error {
	id := newBlockID("bp-")

	logFingerprint := fingerprint
	if logFingerprint == "" {
		logFingerprint = "(missing)"
	}
	bp.logger.Info("blocked request",
		zap.String("block_id", id),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("fingerprint", logFingerprint),
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
