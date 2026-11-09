// Package turnstile provides Cloudflare Turnstile challenges for Caddy.
package turnstile

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	caddy.RegisterModule(Turnstile{})

	httpcaddyfile.RegisterHandlerDirective("turnstile", parseTurnstileCaddyfile)

	// Challenge before rewrite, redir and try_files unless route order
	// is made explicit. Native Caddy matchers compose the policy.
	httpcaddyfile.RegisterDirectiveOrder("turnstile", httpcaddyfile.Before, "redir")
}
