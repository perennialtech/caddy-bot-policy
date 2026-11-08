// Package botpolicy provides Caddy policy matching for IP addresses,
// User-Agent headers and ASNs, and Cloudflare Turnstile challenges.
package botpolicy

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	caddy.RegisterModule(BotPolicy{})
	caddy.RegisterModule(Turnstile{})

	httpcaddyfile.RegisterHandlerDirective("bot_policy", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("turnstile", parseTurnstileCaddyfile)

	// Evaluate policy and challenge on the original request URI, before
	// rewrite, redir, and try_files. Blocklisted clients cannot be cleared
	// by Turnstile.
	httpcaddyfile.RegisterDirectiveOrder("bot_policy", httpcaddyfile.Before, "redir")
	httpcaddyfile.RegisterDirectiveOrder("turnstile", httpcaddyfile.Before, "redir")
}
