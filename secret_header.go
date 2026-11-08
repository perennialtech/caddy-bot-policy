package botpolicy

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/textproto"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/http/httpguts"
)

// MatchSecretHeader compares a request header with a provision-time-resolved
// secret. Header names are case-insensitive, and values are matched exactly.
// The secret is not logged by this module. Custom headers are still exposed
// by Caddy access logs unless filtered and forwarded upstream unless removed.
type MatchSecretHeader struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	secret []byte
}

func (MatchSecretHeader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.matchers.secret_header", New: func() caddy.Module { return new(MatchSecretHeader) }}
}

func (m *MatchSecretHeader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.Name, &m.Value) || d.NextArg() {
			return d.Err("secret_header requires a header name and secret value")
		}
		if d.NextBlock(0) {
			return d.Err("secret_header does not accept a block")
		}
	}
	return nil
}

func (m *MatchSecretHeader) Provision(_ caddy.Context) error {
	if !httpguts.ValidHeaderFieldName(m.Name) {
		return fmt.Errorf("secret_header: invalid header name")
	}
	m.Name = textproto.CanonicalMIMEHeaderKey(m.Name)
	m.secret = []byte(caddy.NewReplacer().ReplaceKnown(m.Value, ""))
	if len(m.secret) == 0 {
		return fmt.Errorf("secret_header: secret value must not be empty")
	}
	return nil
}

func (m *MatchSecretHeader) Match(r *http.Request) bool {
	for _, value := range r.Header.Values(m.Name) {
		if subtle.ConstantTimeCompare([]byte(value), m.secret) == 1 {
			return true
		}
	}
	return false
}

var (
	_ caddy.Provisioner        = (*MatchSecretHeader)(nil)
	_ caddyhttp.RequestMatcher = (*MatchSecretHeader)(nil)
)
