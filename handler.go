package botpolicy

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// observedFingerprint is a trusted, package-private per-request value. Caddy
// request variables can be written by arbitrary other directives, so they
// must not be the authority for bound clearance verification.
type observedFingerprint struct {
	exactName, bindName string
	exact, bind         string
}

type observedFingerprintKey struct{}

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
// The listener wrapper must be configured too — see ListenerWrapper — and,
// for HTTP/3, the packet conn wrapper (PacketConnWrapper). Without them the
// variable is simply never set.
type Handler struct {
	// VarName is the http.vars.* key to publish the fingerprint under.
	// Defaults to "ja4", making it available as {http.vars.ja4}.
	VarName string `json:"var_name,omitempty"`
	// BindVarName publishes the resumption-insensitive variant. It is not
	// spec-exact JA4 and should not be used for a JA4 blocklist.
	BindVarName string `json:"bind_var_name,omitempty"`

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
	if h.BindVarName == "" {
		h.BindVarName = "ja4_bind"
	}
	if !varNamePattern.MatchString(h.VarName) || !varNamePattern.MatchString(h.BindVarName) || h.VarName == h.BindVarName {
		return errors.New("ja4: var_name and bind_var_name must be distinct valid variable names")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
//
// Always overwrite both fingerprint variables, including when the listener
// could not observe a ClientHello. This prevents earlier request-derived vars
// from being mistaken for a trusted wire fingerprint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	store := conns.getPair
	key := ""
	if r.ProtoMajor == 3 {
		// The QUIC sniffer records Initial packets by UDP source address.
		store = quicConns.getPair
		key = normalizeAddr(r.RemoteAddr)
	} else if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		key = tcpConnectionKey(r.RemoteAddr, local.String())
	}
	fp := store(key)
	// Clear preexisting vars even when no ClientHello was captured.
	caddyhttp.SetVar(r.Context(), h.VarName, fp.ja4)
	caddyhttp.SetVar(r.Context(), h.BindVarName, fp.bind)
	r = r.WithContext(context.WithValue(r.Context(), observedFingerprintKey{}, observedFingerprint{
		exactName: h.VarName, bindName: h.BindVarName, exact: fp.ja4, bind: fp.bind,
	}))
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			sub := d.Val()
			switch sub {
			case "var_name", "bind_var_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if sub == "var_name" {
					h.VarName = d.Val()
				} else {
					h.BindVarName = d.Val()
				}
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
