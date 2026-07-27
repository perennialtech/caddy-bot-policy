// Package botpolicy implements the bot_policy Caddy HTTP handler, which
// blocks requests whose TLS client fingerprint (JA4) is on a configured
// blocklist. The fingerprint itself is not computed by this module; it is
// read from a Caddy request variable set upstream by a fingerprinting
// module such as github.com/matt-/caddy-ja4.
package botpolicy

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	caddy.RegisterModule(BotPolicy{})
	httpcaddyfile.RegisterHandlerDirective("bot_policy", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("bot_policy", httpcaddyfile.Before, "basicauth")
}
