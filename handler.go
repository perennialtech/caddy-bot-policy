package botpolicy

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Handler publishes the JA4 fingerprint captured by the ja4 listener wrapper
// into a request variable, so that it can be read by bot_policy, matched on,
// or written to the access log with log_append.
//
// It is a separate directive from bot_policy on purpose: a site can run the
// ja4 handler alone to observe fingerprints without blocking anything, which
// is the sane way to build a blocklist in the first place.
//
//	ja4 {
//		var_name ja4
//	}
//
// The listener wrapper must be configured too — see ListenerWrapper. Without
// it the variable is simply never set.
type Handler struct {
	// VarName is the http.vars.* key to publish the fingerprint under.
	// Defaults to "ja4", making it available as {http.vars.ja4}.
	VarName string `json:"var_name,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up h.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.VarName == "" {
		h.VarName = defaultVarName
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
//
// A request with no fingerprint leaves the variable unset rather than setting
// it to the empty string, so that {http.vars.ja4} renders as empty in logs
// and bot_policy sees the same "missing" case either way.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if fingerprint := conns.get(normalizeAddr(r.RemoteAddr)); fingerprint != "" {
		caddyhttp.SetVar(r.Context(), h.VarName, fingerprint)
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "var_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VarName = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized ja4 subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// parseJA4Caddyfile sets up a ja4 handler from Caddyfile tokens.
func parseJA4Caddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	if err := handler.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &handler, nil
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
