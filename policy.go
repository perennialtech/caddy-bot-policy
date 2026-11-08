package botpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// BotPolicy applies whitelists and blacklists to client IP addresses,
// TLS client fingerprints (JA4), and User-Agent headers. Fingerprints come
// from the ja4 handler, which needs the ja4 listener or packet conn wrapper
// to have captured the ClientHello.
type BotPolicy struct {
	// VarName names the fingerprint to match: the ja4 handler's var_name or
	// bind_var_name. It is read from the ja4 handler directly, not from the
	// request variable, which other directives can overwrite. Defaults to
	// "ja4".
	VarName string `json:"var_name,omitempty"`

	// Whitelist contains JA4 identifiers, IPv4/IPv6 addresses and CIDRs,
	// and ua:-prefixed Go regular expressions for User-Agent headers.
	// Any match bypasses on_missing_fingerprint closed and downstream
	// Turnstile challenges, unless Blacklist also matches.
	// IP matching uses Caddy's resolved client IP, respecting trusted_proxies.
	// At least one entry in Whitelist or Blacklist is required.
	Whitelist []string `json:"whitelist,omitempty"`

	// Blacklist accepts the same entries as Whitelist. Any match receives
	// a 403, regardless of JA4/IP whitelist matches or Turnstile clearance.
	// Blacklist always wins, regardless of prefix length or entry order.
	// Both lists are validated when the configuration is provisioned.
	Blacklist []string `json:"blacklist,omitempty"`

	// OnMissingFingerprint is "open" (let the request through when the ja4
	// handler published no fingerprint under var_name) or "closed" (block
	// it). Defaults to "open". IP blacklist and whitelist matches are
	// evaluated first, even when the fingerprint is missing. User-Agent
	// matches are also evaluated before the missing-fingerprint policy.
	OnMissingFingerprint string `json:"on_missing_fingerprint,omitempty"`

	// Action is the response taken when a request is blocked. Only
	// "block-403" is currently supported: responds 403 and attaches a
	// unique block ID for tracing/support.
	Action string `json:"action,omitempty"`

	whitelist policyList
	blacklist policyList
	logger    *zap.Logger
}

// A private context key carries whitelist matches to downstream Turnstile
// handlers without making a request variable an authorization decision.
type policyWhitelistKey struct{}

type policyList struct {
	fingerprints map[string]bool
	ips          caddyhttp.MatchClientIP
	userAgents   []*regexp.Regexp
}

// Matches the fixed-width identifiers produced by clientHello.ja4,
// including the uppercase ALPN characters permitted by alpnCode.
var ja4Identifier = regexp.MustCompile(`^[tq]([0-9]{2}|s[123])[di][0-9]{4}[a-zA-Z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

func (list *policyList) provision(ctx caddy.Context, entries []string) error {
	list.fingerprints = make(map[string]bool)
	list.ips = caddyhttp.MatchClientIP{}
	list.userAgents = nil
	for _, entry := range entries {
		if pattern, ok := strings.CutPrefix(entry, "ua:"); ok {
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

func (list policyList) match(r *http.Request, fingerprint string) (bool, error) {
	if list.fingerprints[fingerprint] {
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
	return bp.Validate()
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
	blacklisted, err := bp.blacklist.match(r, fingerprint)
	if err != nil {
		return err
	}
	if blacklisted {
		return bp.block(w, r, fingerprint)
	}
	whitelisted, err := bp.whitelist.match(r, fingerprint)
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
	_ caddy.Validator             = (*BotPolicy)(nil)
	_ caddyhttp.MiddlewareHandler = (*BotPolicy)(nil)
)
