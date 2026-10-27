// Package botpolicy implements JA4 TLS client fingerprinting for Caddy and a
// policy handler that blocks requests by fingerprint, plus a Cloudflare
// Turnstile challenge whose clearance can be bound to that fingerprint.
//
// It registers five modules:
//
//	caddy.listeners.ja4       listener wrapper that reads the ClientHello and
//	                          computes the JA4 fingerprint
//	caddy.packetconns.ja4     packet conn wrapper that does the same for QUIC
//	                          (HTTP/3) from Initial packets
//	http.handlers.ja4         publishes that fingerprint as a request variable
//	http.handlers.bot_policy  blocks requests whose fingerprint is blocklisted
//	http.handlers.turnstile   requires a Cloudflare Turnstile clearance
//	                          cookie, serving a challenge page without one
//
// The split exists because a JA4 can only be computed before TLS is
// terminated, while policy can only be applied once the request is parsed.
// The two halves meet through a request variable, which also makes the
// fingerprint available to log_append and to request matchers.
//
// Minimal configuration:
//
//	{
//		servers {
//			listener_wrappers {
//				ja4
//				tls
//			}
//		}
//	}
//
//	example.com {
//		ja4
//		bot_policy {
//			block t13d1516h2_8daaf6152771_e5627efa2ab1
//		}
//		reverse_proxy localhost:8080
//	}
package botpolicy

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

// defaultVarName is the http.vars.* key the fingerprint is published under,
// and the one bot_policy reads by default.
const defaultVarName = "ja4"

func init() {
	caddy.RegisterModule(ListenerWrapper{})
	caddy.RegisterModule(PacketConnWrapper{})
	caddy.RegisterModule(Handler{})
	caddy.RegisterModule(BotPolicy{})
	caddy.RegisterModule(Turnstile{})

	httpcaddyfile.RegisterHandlerDirective("ja4", parseJA4Caddyfile)
	httpcaddyfile.RegisterHandlerDirective("bot_policy", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("turnstile", parseTurnstileCaddyfile)

	// Order matters here in two senses. bot_policy has to run after ja4 has
	// published the fingerprint, and RegisterDirectiveOrder can only anchor
	// against directives from Caddy's standard distribution — it panics on
	// anything else, so "ja4 before bot_policy" is not expressible directly.
	// Anchoring all three before redir, in this order, leaves the list as
	// [... header, request_body, ja4, bot_policy, turnstile, redir, method,
	// rewrite, uri, try_files ...]: the fingerprint is published first,
	// blocklisted clients never get a challenge, and turnstile can bind its
	// clearance to the fingerprint.
	//
	// Running ahead of redir, rewrite, uri and try_files means that matchers
	// on these three directives see the URL the visitor actually requested. A path-scoped
	// turnstile cannot be sidestepped by a rewrite that happens to move a
	// protected URL elsewhere, and the challenge form, which posts back to
	// the requested URL, reaches the same route as the request it answers.
	httpcaddyfile.RegisterDirectiveOrder("ja4", httpcaddyfile.Before, "redir")
	httpcaddyfile.RegisterDirectiveOrder("bot_policy", httpcaddyfile.Before, "redir")
	httpcaddyfile.RegisterDirectiveOrder("turnstile", httpcaddyfile.Before, "redir")
}
