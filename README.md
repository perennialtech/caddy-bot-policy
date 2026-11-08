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

## Run as a separate proxy

To keep an existing reverse proxy for TLS and routing, run Caddy with
this plugin between that proxy and the backend:

```
client → nginx (TLS, routing) → Caddy with turnstile → backend
```

[examples/proxy](examples/proxy) runs this with Docker Compose:
`docker compose up --build` in that directory, then open
`https://localhost` (accept the self-signed certificate warning for this
local example). nginx generates a self-signed certificate at startup; use
a trusted certificate for real sites. The example builds the filter from
the current checkout and uses Cloudflare's testing keys unless you set
`TURNSTILE_SITE_KEY` and
`TURNSTILE_SECRET_KEY`. The filter takes its listen address, upstream and
trusted proxies from `BIND`, `TARGET` and `TRUSTED_PROXIES`.

CI publishes `ghcr.io/perennialtech/caddy-bot-policy:latest` and
`sha-<commit SHA>` images on pushes to `main`. To use a published image,
replace the filter's `build` in Compose with `image:` pointing at that tag.
Authenticate to GHCR if the package is private.

The front proxy and the filter must agree on a few things:

- Set `trusted_proxies` on the filter to the front proxy's addresses.
  Otherwise `client_ip` matchers and Turnstile's `remoteip` see the proxy's
  address instead of the visitor's.
- Forward the visitor's address in `X-Forwarded-For`, or configure the
  filter's `client_ip_headers` for another header that the front proxy
  overwrites (nginx: `proxy_set_header X-Real-IP $remote_addr;` with
  `client_ip_headers X-Real-IP` on the filter). If the front proxy appends
  to incoming `X-Forwarded-For`, enable `trusted_proxies_strict` on the
  filter to prevent client-supplied addresses from bypassing IP rules.
- Forward the original `Host` header. Turnstile verifies the hostname on
  which the challenge was solved. Caddy and Traefik preserve it by default;
  nginx needs `proxy_set_header Host $host`.
- Leave `allow_insecure_cookie` off. The filter receives HTTP, but visitors
  use HTTPS, so the clearance cookie must remain `Secure`.

The filter receives each request's original `Host`, so one instance can
serve multiple sites. The operational requirements below also apply.

### Route cleared requests directly from nginx

For sites where nginx should handle application routing, the front proxy can
validate the filter's stateless HMAC-SHA256 clearance cookie and send cleared
requests straight to the application. Only requests without valid clearance
go to Caddy for the Turnstile challenge and verification POST:

```text
client → nginx ── valid clearance ──→ application
              └── otherwise ───────→ Caddy (Turnstile)
```

The example consists of [nginx configuration](examples/proxy/advanced.nginx.conf),
an [njs cookie validator](examples/proxy/advanced-clearance.js) and a
[challenge-only Caddyfile](examples/proxy/advanced.filter.Caddyfile).
Install nginx's HTTP [njs module](https://nginx.org/en/docs/njs/install.html),
load the nginx configuration as the main `nginx.conf`, and place the
validator at `/etc/nginx/advanced-clearance.js`. Set the same
`BP_CLEARANCE_KEY` (at least 32 bytes) and `TURNSTILE_SITE_KEY` in
both processes; only Caddy needs `TURNSTILE_SECRET_KEY`. Replace the
hostname, TLS certificate paths and upstream addresses for your deployment.
Keep both upstreams inaccessible to untrusted clients.

The example matches the plugin's default `bp_clearance` cookie prefix
and a 30-day TTL. Its validator checks the derived cookie name, signature,
hostname and issue time; simply checking cookie presence is insufficient.
If you change the cookie format, prefix, site key or TTL, update the validator
to match. The shared clearance key is distinct from the Turnstile API secret.

**nginx now owns policy selection.** Put any IP blocks, trusted-client bypasses
and path exclusions in nginx before its clearance check. Caddy cannot enforce
those policies on requests that nginx sends directly to the application.

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

Go integration tests exercise Caddy routing with manually replayed cookies,
not browser cookie handling. `test/browser/` contains an optional browser
integration test against Cloudflare's public Turnstile testing keys. Its
`run.py` describes additional dependencies; it is not part of CI.
