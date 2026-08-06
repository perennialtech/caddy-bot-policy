package botpolicy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// BotPolicy is an HTTP middleware that blocks requests whose TLS client
// fingerprint (JA4) matches an entry on a configured blocklist. The
// fingerprint is not computed here; it is read from the request variable
// published by the ja4 handler, which in turn needs the ja4 listener wrapper
// to have captured the ClientHello.
//
// Example Caddyfile usage:
//
//	bot_policy {
//		var_name               ja4
//		block                  t13d1517h2_8daaf6152771_b6f405a00624
//		block                  q13d0312h3_55b375c5d22e_cd8dafe46ac5
//		on_missing_fingerprint open
//		action                 block-403
//	}
type BotPolicy struct {
	// VarName is the http.vars.* key that holds the fingerprint published
	// by the ja4 handler. Defaults to "ja4".
	VarName string `json:"var_name,omitempty"`

	// Blocked is the list of JA4 fingerprints to block. At least one is
	// required.
	Blocked []string `json:"blocked,omitempty"`

	// OnMissingFingerprint is "open" (let the request through when the
	// configured var_name variable is empty/unset) or "closed" (block
	// it). Defaults to "open".
	OnMissingFingerprint string `json:"on_missing_fingerprint,omitempty"`

	// Action is the response taken when a request is blocked. Only
	// "block-403" is currently supported: responds 403 and attaches a
	// unique block ID for tracing/support.
	Action string `json:"action,omitempty"`

	blocked map[string]bool
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (BotPolicy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.bot_policy",
		New: func() caddy.Module { return new(BotPolicy) },
	}
}

// Provision sets up bp, indexing the blocked fingerprints for O(1) lookup.
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

	if len(bp.Blocked) == 0 {
		return fmt.Errorf("bot_policy: at least one 'block' entry is required")
	}

	blocked := make(map[string]bool, len(bp.Blocked))
	for _, fp := range bp.Blocked {
		blocked[fp] = true
	}
	bp.blocked = blocked

	return nil
}

// Validate ensures bp is ready to serve requests.
func (bp *BotPolicy) Validate() error {
	if len(bp.blocked) == 0 {
		return fmt.Errorf("bot_policy: no blocked fingerprints parsed")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (bp *BotPolicy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fingerprint, _ := caddyhttp.GetVar(r.Context(), bp.VarName).(string)

	var shouldBlock bool
	switch {
	case fingerprint == "":
		shouldBlock = bp.OnMissingFingerprint == "closed"
	default:
		shouldBlock = bp.blocked[fingerprint]
	}

	if !shouldBlock {
		return next.ServeHTTP(w, r)
	}
	return bp.block(w, r, fingerprint)
}

func (bp *BotPolicy) block(w http.ResponseWriter, r *http.Request, fingerprint string) error {
	id := generateBlockID()

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

	w.Header().Set("X-Block-Id", id)
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "403 Forbidden (block id: %s)\n", id)
	return nil
}

func generateBlockID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "bp-" + hex.EncodeToString(b[:])
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*BotPolicy)(nil)
	_ caddy.Validator             = (*BotPolicy)(nil)
	_ caddyhttp.MiddlewareHandler = (*BotPolicy)(nil)
)
