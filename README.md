# caddy-bot-policy

A [Caddy](https://caddyserver.com) module for observing JA4 TLS client
fingerprints, blocking selected fingerprints, and issuing
[Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
challenge clearances.

## Install

Build Caddy with the plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/perennialtech/caddy-bot-policy
```

Use [examples/observe.Caddyfile](examples/observe.Caddyfile) to start
recording JA4 in access logs. Replace `example.com` and the upstream
address, then run:

```sh
./caddy run --config examples/observe.Caddyfile
```

The `ja4` listener wrapper must run before `tls`. HTTP/3 uses the separate
`packet_conn_wrappers` block (requires Caddy 2.11 or later). Without it,
HTTP/3 requests have no captured fingerprint.

## Configure policies and challenges

- `ja4` publishes the spec-exact `{http.vars.ja4}` for logs and
  blocklists, and the resumption-insensitive `{http.vars.ja4_bind}` for
  clearance binding.
- `bot_policy` blocks explicitly listed JA4 values. Choose
  `on_missing_fingerprint` deliberately; a missing fingerprint is not
  proof of bad traffic.
- `turnstile` serves a challenge until the client presents a signed
  clearance. Supply site and secret keys for your hostname. It does not
  require Cloudflare to proxy your site or require fingerprint binding.

For a combined policy with binding, start with
[examples/turnstile-bound.Caddyfile](examples/turnstile-bound.Caddyfile).
Replace the example blocklist entry and upstream, and supply
`TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`.

The canonical configuration reference is the module's Caddyfile parser and
option comments in [handler.go](handler.go), [policy.go](policy.go),
[turnstile.go](turnstile.go), [listener.go](listener.go) and
[packetconn.go](packetconn.go). The source files also define the supported
options and their validation.

### Caddyfile options

| Directive | Options |
|---|---|
| `ja4` | `var_name`, `bind_var_name` |
| `bot_policy` | `block` (repeatable, required), `var_name`, `on_missing_fingerprint` (`open` or `closed`), `action` (`block-403`) |
| `turnstile` | `site_key`, `secret_key` (required), `clearance_ttl`, `clearance_key`, `cookie_name`, `bind_fingerprint`, `max_pending_verifications`, `allow_insecure_cookie` |
| TCP `listener_wrappers ja4`, UDP `packet_conn_wrappers ja4` | `max_capture_bytes` |

Use `bind_fingerprint` with the variable name published by the `ja4`
handler's `bind_var_name`; changing one requires changing the other.
`{http.vars.ja4_bind}` is for clearance binding, not a spec-exact JA4
blocklist. To pass a fingerprint upstream, use
`header_up X-JA4 {http.vars.ja4}` within `reverse_proxy`, so a
client-supplied header cannot override it.

The `ja4`, `bot_policy` and `turnstile` directives run ahead of
`rewrite` and `try_files` unless you place them in a `route`, whose
order is explicit. Path-scoped Turnstile policies therefore match the
original requested URL; protect any public rewrite aliases as well.
For method-restricted matchers, include both GET and POST. Use matchers
to exclude webhook, API and preflight paths rather than challenging them.

Set `clearance_key` if the signing key must survive Turnstile secret
rotation. A custom `cookie_name` sets the cookie namespace; the signed
policy identity still prevents transplanting cookies between policies.
`allow_insecure_cookie` is strictly for HTTP-only local development,
**never** public deployments or deployments with upstream TLS termination.
`max_pending_verifications` caps concurrent siteverify calls but is not
a request rate limit.

## Operational requirements

**Fingerprint-bound Turnstile must use HTTP/1.1 or HTTP/2 only.**
Set `servers { protocols h1 h2 }` as in the bound example. The plugin
refuses bound clearances on HTTP/3 even if QUIC JA4 observation is enabled:
a decrypted QUIC Initial cannot be reliably associated with the authenticated
HTTP/3 request. QUIC JA4 is useful for telemetry, **not authorization**;
do not rely on it as a security boundary for a blocklist either. A TCP
fingerprint identifies a TLS client profile, not a unique person or device.

**Bound clearance limits cookie reuse, not token redemption.**
A valid Turnstile token solved in one browser can be submitted by a different
client before redemption. If Cloudflare accepts that token, the resulting
cookie is bound to the **submitting client's** fingerprint. Fingerprint
binding neither proves which client solved the widget nor prevents clients
that share or imitate the same TLS profile from reusing a clearance.

**Protect challenge responses and verification requests.**
Match Turnstile on both GET and POST: the verification form posts to the
challenged URL, then redirects to it with GET. Rewrites, GET-only matchers,
and routes must admit the verification POST. Protect the siteverify endpoint
from excessive submissions with an appropriate upstream rate limit.
Deferred response headers must not override the challenge page's CSP or
`Cache-Control: no-store`.

**Do not share-cache cleared pages without enforcing the same policy.**
A CDN or reverse proxy in front of Caddy can otherwise serve a protected
response to a client without clearance. Disable shared caching for protected
paths, or enforce clearance at that cache.

**Account for non-browser traffic.** Webhooks, health checks, cross-origin
OPTIONS preflights, and clients without JavaScript cannot solve the widget;
exclude appropriate paths using matchers. Challenging a POST loses its body
after the verification redirect. Public HTTPS is required for secure cookies,
including when TLS terminates at an upstream proxy. If a PROXY-protocol
listener wrapper is used, put it before `ja4` so the TLS ClientHello is
visible.

## Development and testing

CI runs `gofmt`, `go mod tidy -diff`, `go vet ./...`, and
`go test -race -count=1 ./...`.

`test/browser/` contains an optional browser integration test against
Cloudflare's public Turnstile testing keys. Its `run.py` explains the
additional dependencies; it is not part of CI.
