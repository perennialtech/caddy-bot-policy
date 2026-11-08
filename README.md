# caddy-bot-policy

A [Caddy](https://caddyserver.com) module providing
[Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
challenge clearances. Caddy's native matchers and routes decide which clients
are blocked, allowed, or challenged.

## Install

Build Caddy with the plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build v2.11.9 --with github.com/perennialtech/caddy-bot-policy
```

## Configure policies and challenges

Start with [examples/turnstile.Caddyfile](examples/turnstile.Caddyfile).
Replace its matchers and upstream, and supply `TURNSTILE_SITE_KEY`,
`TURNSTILE_SECRET_KEY`.

Use native Caddy `client_ip` and `header_regexp` matchers to select which
clients are blocked, allowed, or challenged. Put `respond` rules before
allowed `handle` routes, followed by a fallback `handle` containing
`turnstile`. Each `handle` is an alternative (logical OR); matchers within
one named matcher are combined with AND.

The complete example also shows evaluation before rewrites: explicit `route`
order is authoritative. Do not put rewrites ahead of the policy decisions.
Use `path` and `method` matchers to scope checks; a Turnstile-protected
page needs GET and POST for verification.

The `turnstile` handler still serves challenges until the client presents a
signed clearance. Supply keys for your hostname; Cloudflare does not need
to proxy the site. The canonical option references are the Caddyfile parser
in [caddyfile.go](caddyfile.go) and the handler options in
[turnstile.go](turnstile.go).

## Operational requirements

**Protect challenge responses and verification requests.**
Match Turnstile on both GET and POST: its verification form posts to the
challenged URL and then redirects to it with GET. Rewrites, GET-only
matchers, and routes must admit the verification POST. Protect siteverify
from excessive submissions with an appropriate upstream rate limit.
Deferred response headers must not override the challenge page's CSP or
`Cache-Control: no-store`.

**Do not share-cache cleared pages without enforcing the same policy.**
A CDN or reverse proxy in front of Caddy can otherwise serve a protected
response without clearance. Disable shared caching for protected paths, or
enforce clearance at that cache.

**Account for non-browser traffic.** Webhooks, health checks, cross-origin
OPTIONS preflights, and clients without JavaScript cannot solve the widget;
exclude suitable paths using matchers. Challenging a POST loses its body
after verification redirects. Public HTTPS is required for secure cookies,
including when TLS terminates at an upstream proxy.

## Development and testing

Run the gates defined in [.github/workflows/ci.yml](.github/workflows/ci.yml).

`test/browser/` contains an optional browser integration test against
Cloudflare's public Turnstile testing keys. Its `run.py` describes additional
dependencies; it is not part of CI.
