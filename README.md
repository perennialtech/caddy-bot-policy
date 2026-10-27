# caddy-bot-policy

A [Caddy](https://caddyserver.com) plugin that computes the **JA4** TLS client
fingerprint and blocks requests whose fingerprint is on a blocklist. It can
also put a [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
challenge in front of a site, with the clearance optionally bound to the
client's fingerprint.

The plugin provides five modules:

| Module | What it does |
|---|---|
| `caddy.listeners.ja4` | Listener wrapper: reads the raw ClientHello and computes the JA4 (TCP: HTTP/1.1 and HTTP/2) |
| `caddy.packetconns.ja4` | Packet conn wrapper: does the same from QUIC Initial packets (HTTP/3) |
| `http.handlers.ja4` | Publishes spec-exact `ja4` and a resumption-insensitive `ja4_bind` for clearance binding |
| `http.handlers.bot_policy` | Blocks requests whose fingerprint is on the list |
| `http.handlers.turnstile` | Requires a Turnstile clearance cookie, serving a challenge page without one |

They are separate because a JA4 **can only be computed before TLS is
terminated**. Once the handshake completes the ClientHello is gone, and Go's
`tls.ConnectionState` only exposes the negotiated result, not the offered
cipher and extension lists the fingerprint is built from. A policy, on the
other hand, can only be applied once there is a parsed HTTP request. The two
halves exchange trusted fingerprints through a private per-request context
value; the handler also publishes them as request variables for `log_append`,
matchers and observability. Other directives may change those public variables,
but cannot forge a fingerprint used for a Turnstile clearance.

## Configuration

```caddyfile
{
	servers {
		listener_wrappers {
			ja4
			tls
		}
		packet_conn_wrappers {
			ja4
		}
	}
}

example.com {
	ja4 {
		var_name ja4
	}

	bot_policy {
		var_name               ja4
		block                  t13d1517h2_8daaf6152771_b6f405a00624
		block                  q13d0312h3_55b375c5d22e_cd8dafe46ac5
		on_missing_fingerprint open
		action                 block-403
	}

	reverse_proxy localhost:8080
}
```

**The `ja4` wrapper must come before `tls`** in `listener_wrappers`. That
position is exactly what lets it see the handshake before it is encrypted.

The `packet_conn_wrappers` block covers HTTP/3, which Caddy serves by
default alongside HTTP/1.1 and HTTP/2. Leave it out and requests over h3
simply arrive without a fingerprint. There is no `tls` placeholder to order
against here: packet conn wrappers always run before QUIC. HTTP/3
fingerprints start with `q` instead of `t`, so the same browser has a
different JA4 over h3 than over h2 — block both if you mean to block a
client. TLS resumption can also change spec-exact JA4; for a blocklist,
observe and account for the full- and resumed-handshake variants. QUIC
Initials are unauthenticated, so HTTP/3 fingerprints are diagnostic data
and **not a sound security boundary**: an adversarial client can inject an
Initial with another JA4 from the same UDP endpoint. Use h1/h2-only when
security policy relies on a trustworthy JA4 blocklist.

The `ja4`, `bot_policy` and `turnstile` directives order themselves (in that
order, ahead of `redir` and any URL rewriting), so no global `order` lines
are needed unless they share a route with other third-party directives that
need a specific order.

### Observe only, without blocking

`ja4` works on its own. This is the sensible way to start: publish the
fingerprint, write it to the access log, and build your blocklist from real
data before blocking anything.

```caddyfile
example.com {
	ja4
	log {
		output file /var/log/caddy/access.json
		format json
	}
	log_append client_ja4 {http.vars.ja4}
	reverse_proxy localhost:8080
}
```

### Passing the fingerprint upstream

To hand the fingerprint to your application, set it as a request header in
`reverse_proxy`:

```caddyfile
example.com {
	ja4
	reverse_proxy localhost:8080 {
		header_up X-JA4 {http.vars.ja4}
	}
}
```

`header_up` replaces any `X-JA4` header the client sent, including when no
fingerprint is available (the header is then sent empty), so upstreams can
trust it as long as they are only reachable through Caddy. Treat an empty
value as "unknown", not as suspicious.

### Turnstile challenge

`turnstile` puts a Cloudflare Turnstile challenge in front of everything it
covers. It does not need `ja4`, and does not need the site to be proxied
through Cloudflare: create a widget in the Cloudflare dashboard for your
hostname and give the plugin its keys.

```caddyfile
example.com {
	turnstile {
		site_key   {env.TURNSTILE_SITE_KEY}
		secret_key {env.TURNSTILE_SECRET_KEY}
	}
	reverse_proxy localhost:8080
}
```

The flow:

1. A request with a valid clearance cookie goes straight through.
2. Any other request gets a challenge page (status 403, `Cache-Control:
   no-store`) hosting the widget.
3. When the widget is solved, the page posts the token back to **the same
   URL** the visitor asked for. Caddy redeems it with Cloudflare's siteverify
   endpoint and checks that it succeeded, that it was solved on this
   hostname, and that it came from this challenge (its `action`).
4. On success the visitor gets the clearance cookie and is redirected (303)
   to that URL with a GET. On failure they get a 403 page with a "try again"
   link back to it and a block ID (also in `X-Block-Id`, prefixed `ts-`),
   and no cookie. Nothing about the client is remembered or banned:
   following the link shows a fresh challenge. If Cloudflare cannot be
   reached, the answer is a 503 with the same link rather than a block.

Posting back to the requested URL, rather than to a fixed endpoint, means
the submission goes through exactly the same routes and matchers as the
request it answers. A path-scoped `turnstile` receives its own submissions,
and a `rewrite` or `try_files` in front of it changes both requests the same
way. The form action and the redirect always use the URL as the visitor sent
it, before any rewrite or `handle_path` prefix stripping.

**Matchers must admit verification POSTs.** Do not scope `turnstile` with
`method GET` alone, or place it inside a GET-only `handle`/`route`: the GET
would show a challenge, but its POST would miss the verifier. For a
method-restricted route, use `method GET POST` alongside the path matcher,
or place `turnstile` before the method-specific routing.

Combined with the blocklist, known-bad fingerprints are refused outright and
other visitors can reuse their clearance for up to 30 days per binding
profile (subject to browser cookie retention and further fingerprint changes):

```caddyfile
{
    servers {
        # Required for fingerprint-bound Turnstile: QUIC Initials do not
        # authenticate the fingerprint of the established HTTP/3 connection.
        protocols h1 h2
        listener_wrappers {
            ja4
            tls
        }
    }
}

example.com {
	ja4
	bot_policy {
		block t13d1517h2_8daaf6152771_b6f405a00624
	}
	turnstile {
		site_key         {env.TURNSTILE_SITE_KEY}
		secret_key       {env.TURNSTILE_SECRET_KEY}
		bind_fingerprint
	}
	reverse_proxy localhost:8080
}
```

#### Directive order and matchers

`ja4`, `bot_policy` and `turnstile` sort themselves early: after `header`
and `request_body`, before `redir`, `rewrite`, `uri` and `try_files`. Their
matchers therefore see **the URL the visitor requested**, not a rewritten
one. With `try_files {path} /index.html`, `turnstile /app/*` still protects
`/app/anything`, even though the file actually served is `/index.html`.

The flip side: if you rewrite a public URL onto protected content (`rewrite
/promo /app/promo`), protect the public URL too, or use an unscoped
`turnstile` with exclusions. Inside a `route` block directives run in the
order written, so put `turnstile` before any rewrite there.

Like any handler directive, `turnstile` takes a matcher, so it can be kept
off paths that are not loaded by a browser:

```caddyfile
@browser not path /api/* /webhooks/* /.well-known/*
turnstile @browser {
	site_key   {env.TURNSTILE_SITE_KEY}
	secret_key {env.TURNSTILE_SECRET_KEY}
}
```

#### What a clearance is, and is not

The clearance is a **stateless bearer token**: the cookie holds its issue
time and an HMAC-SHA256 over that time, the policy identity (site key,
fingerprint variable and cookie prefix), the hostname and (if bound) the
fingerprint. A clearance from another policy is rejected even if both
policies deliberately share a `clearance_key` and a client copies the value
to the other cookie name. There is no server-side store, so clearances survive restarts
and work across several Caddy instances that share the same keys. It is
worth being precise about what that buys:

- **Integrity.** Nobody can forge or extend a clearance without the signing
  key, or move one to another hostname.
- **Replay resistance is limited.** A clearance is valid until it expires,
  from anything that presents it. Without binding, any client can reuse a
  cookie copied from a browser that solved the challenge. With
  `bind_fingerprint`, it only works from a client with the same stable
  fingerprint profile; this is not cryptographic client authentication.
- **No client identity.** A fingerprint identifies a *kind* of TLS client
  (a browser version on a platform), not a device. A bot that solves the challenge in
  a real browser and replays the cookie from a client mimicking that
  browser's TLS stack passes, for the whole TTL.

So this raises the cost of scraping from cheap HTTP clients: they have to run
a real browser, or faithfully reproduce one's TLS stack, at least once per
clearance. It does not stop browser automation, and it does not stop one
solver sharing its clearance with others. If that matters, shorten
`clearance_ttl` (each solve buys less), and combine it with rate limiting.

Expiry is checked against the issue time and the TTL configured *now*, so
shortening `clearance_ttl` applies to existing cookies straight away. The
cookie is `HttpOnly`, `SameSite=Lax`, **always `Secure` by default**, and
host-only. In particular, this is also true when Caddy receives HTTP from an
upstream TLS-terminating proxy. The external hostname **must be HTTPS** for
the browser to send its clearance back; configure TLS on the public-facing
proxy and redirect public HTTP to HTTPS. Arbitrary `X-Forwarded-Proto` headers
are not used to decide cookie security. For strictly HTTP-only local
development, opt in with `allow_insecure_cookie` (never use it in production).
The cookie name has a keyed suffix derived from the signing configuration
and, when bound, the full fingerprint, so independent Turnstile policies
on one host do not overwrite each other's clearances. Instances using the
same signing key, site key, binding variable and cookie prefix intentionally
share a cookie namespace. Cookie values themselves also authenticate the
policy; the cookie name is not a trust boundary. Version-1 and version-2
clearances issued by previous builds are invalidated and will trigger a
fresh challenge. Browsers do not separate cookies by port.

#### Protecting the verification step

Every challenge submission costs an outbound call to Cloudflare, and anyone
can submit one without solving anything. The handler rejects empty and
oversized tokens without a call, caps the request body at 16 KiB, and caps
the number of calls **in flight** per `turnstile` handler
(`max_pending_verifications`, default 64). Submissions beyond that get a 503
without reaching Cloudflare. This bounds the goroutines and connections a
flood can tie up, but it is not a rate limit. For production, limit POSTs
per client in front of it, for example with
[`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) on `method
POST`, or with your load balancer or firewall.

For Caddy built with `github.com/mholt/caddy-ratelimit`, put a per-client
POST budget *before* `turnstile` in a `route` block, where directive order is
explicit:

```caddyfile
example.com {
    @posts method POST
    route {
        rate_limit @posts {
            zone verification_posts {
                key    {client_ip}
                window 1m
                events 60
            }
        }
        turnstile {
            site_key   {env.TURNSTILE_SITE_KEY}
            secret_key {env.TURNSTILE_SECRET_KEY}
        }
        reverse_proxy localhost:8080
    }
}
```

This limits *all* POSTs on the site, not just Turnstile submissions; scope
the matcher to protected paths and tune the budget for actual traffic.

#### Content Security Policy

The challenge and status pages set their own `Content-Security-Policy`,
replacing any set earlier in the route by a `header` directive. A site's
policy is written for the site's pages and would usually block Turnstile.
The page's policy follows Cloudflare's recommended nonce-based setup:

```
script-src 'nonce-…' 'strict-dynamic' https://challenges.cloudflare.com;
frame-src https://challenges.cloudflare.com;
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'
```

with a fresh nonce on every response, so no `'unsafe-inline'` is needed. A
`header` directive that sets its CSP with `defer` (or `>`) runs after the
handler and would overwrite this policy. The same applies to a deferred
`Cache-Control` header: setting `public` or a positive `max-age` after the
handler may cache the challenge, even though it sets `no-store`. Keep
deferred CSP and cache headers off challenged paths, or configure them to
preserve these response protections. The challenge uses
`Referrer-Policy: strict-origin-when-cross-origin`, so Cloudflare receives
the origin but not the path or query. The `frame-ancestors 'self'` rule
allows same-origin embedding, but disallows embedding from other origins.

#### Things to know

- **Only browsers with JavaScript can pass.** API clients, feeds, health
  checks and webhooks that hit a challenged path get the 403 challenge page.
  Exclude them with a matcher.
- **Non-GET requests lose their body.** A POST without clearance is
  answered with the challenge, and after solving it the visitor is
  redirected to the same URL with a GET. In practice the first request of a
  visit is a GET, so this rarely matters.
- **Search engine crawlers are challenged too.** Exclude them by matcher if
  you need them indexed.
- **CORS preflights cannot pass.** Browsers don't attach clearance cookies
  to cross-origin `OPTIONS` preflight requests. Exclude `OPTIONS` from the
  challenge matcher (and handle CORS normally) if you protect credentialed
  cross-origin requests.
- **Shared caches need explicit protection.** A CDN or other cache in front
  of Caddy must not serve cleared protected responses to clients that have
  not cleared the challenge. Disable shared caching on protected paths or
  enforce the same clearance policy at the caching layer. This handler only
  controls challenge responses, not caches in front of it.
- **Testing keys.** Cloudflare's
  [dummy keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
  work, for local development. Siteverify answers them with
  `hostname: example.com`, no `action`, and a `result_with_testing_key`
  flag. Only those public secrets can produce that flag, so for flagged
  results the hostname and action checks are skipped (and logged as a
  warning). A warning is also logged at startup when a testing secret is
  configured.

### `turnstile` subdirectives

| Subdirective | Values | Description |
|---|---|---|
| `site_key` | Turnstile site key | Required. |
| `secret_key` | Turnstile secret key | Required. `{env.*}` placeholders are expanded when the config loads, so the secret need not appear in the Caddyfile. |
| `clearance_ttl` | duration (default `30d`) | How long a clearance stays valid after it is issued. Between `1m` and `400d` (the longest browsers keep a cookie). |
| `clearance_key` | string of at least 32 bytes | Optional. Key that signs the cookie. By default one is derived from `secret_key`, which means **rotating the Turnstile secret invalidates every clearance**. Set this to rotate them independently. |
| `cookie_name` | cookie prefix (default `bp_clearance`) | Prefix for a cookie name with a keyed configuration suffix and, when bound, a full-fingerprint suffix. Validated when the config loads. |
| `allow_insecure_cookie` | no arguments (default off) | Issue clearance cookies without `Secure` for **HTTP-only local development**. Never enable on public sites or behind HTTPS-terminating proxies. |
| `bind_fingerprint` | `[var_name]` (default `ja4_bind`) | Ties clearance to a fingerprint supplied by the trusted `ja4` handler, not a user-writable request variable. HTTP/1.1 and HTTP/2 only. See below. |
| `max_pending_verifications` | integer (default `64`) | Most siteverify calls this handler has in flight at once. See [Protecting the verification step](#protecting-the-verification-step). |

### Binding the clearance to the fingerprint

With `bind_fingerprint`, a clearance is only accepted from a client with the
same resumption-insensitive fingerprint it was issued to. A cookie copied
out of a real browser and replayed from `curl` or a Python script presents
a different TLS stack, so it is
rejected and that client is challenged again. See [What a clearance is, and
is not](#what-a-clearance-is-and-is-not) for what this does not cover. It
needs the `ja4` handler and TCP listener wrapper set up as above.
**Disable HTTP/3** with `servers { protocols h1 h2 }` when using this
option. QUIC Initial packets aren't tied to the authenticated connection,
so an HTTP/3 request will never be granted a bound clearance. Unbound
Turnstile still works over HTTP/3.

**A fingerprint is required.** With binding on, a request without one is
never cleared, and a challenge solved from one is refused *before* calling
Cloudflare, with a warning in the log. This happens if the `ja4` handler or
TCP listener wrapper is missing, the request is HTTP/3, or the
`bind_fingerprint` argument does not match the `ja4` handler's published
`var_name` or `bind_var_name`. This uses private per-request data, not
`http.vars`, so an earlier `vars` or `map` directive cannot fake it.

**Each binding profile gets its own cookie.** The `ja4` handler publishes both
`{http.vars.ja4}` (spec-exact, for blocklists and logs) and
`{http.vars.ja4_bind}` (for Turnstile). The binding variant removes
`pre_shared_key` (0x0029), `early_data` (0x002a) and `padding` (0x0015)
from the extension count and hash, making it stable across the normal TLS
1.3 full-to-resumed handshake transition. It is **not standard JA4** and
must not be used as a JA4 blocklist entry. Explicitly configuring
`bind_fingerprint ja4` retains exact-JA4 behavior, including a further
challenge when a session resumes. The default may require new clearances
after upgrading from earlier versions. Genuinely different TCP TLS/ALPN
profiles still get separate cookies; later changes to the fingerprint may
still require another solve. Bound HTTP/3 clearances are not supported.
Cookie names begin with `bp_clearance_` unless `cookie_name` is customised.

### `ja4` subdirectives

| Subdirective | Values | Description |
|---|---|---|
| `var_name` | variable name (default `ja4`) | The `http.vars.*` key the fingerprint is published under. |
| `bind_var_name` | variable name (default `ja4_bind`) | The key for the resumption-insensitive variant; set this to match a custom `turnstile bind_fingerprint <var_name>`. Must differ from `var_name`. |

### Listener and packet conn wrapper options

Both wrappers accept the same option:

| Option | Values | Description |
|---|---|---|
| `max_capture_bytes` | integer (default `16384`) | The largest ClientHello that will be buffered (TCP) or reassembled from CRYPTO frames (QUIC). A single TLS record tops out at 16 KiB; hellos carrying post-quantum key shares already exceed 2 KiB. |

### `bot_policy` subdirectives

| Subdirective | Values | Description |
|---|---|---|
| `var_name` | variable name (default `ja4`) | Must match the `var_name` of the `ja4` directive. |
| `block` | JA4 fingerprint | Repeatable; several values may be given on one line. At least one is required. |
| `on_missing_fingerprint` | `open` \| `closed` (default `open`) | What to do when there is no fingerprint: no TLS, HTTP/3 without the packet conn wrapper, or an unreadable ClientHello. `open` lets the request through, `closed` blocks it. |
| `action` | `block-403` (the only supported value) | Responds 403 with an `X-Block-Id` header carrying a unique ID (prefixed `bp-`, distinct from `network_policy`'s `np-`) and logs the blocked request. |

## Limitations

- **HTTP/3 needs Caddy 2.11 or newer**, the first release with
  `packet_conn_wrappers`. On older versions the block is a config error.
- **QUIC fingerprints cannot authenticate the live connection.** The UDP
  packet wrapper observes unauthenticated Initial packets, keyed by source
  address. Another Initial from the same socket (or a source-spoofed packet)
  can replace the fingerprint attributed to an already-established HTTP/3
  connection; migration to a new address loses the original fingerprint.
  Therefore, with `turnstile bind_fingerprint` an HTTP/3 request always
  fails closed, including a verification POST. **Disable HTTP/3** on sites
  requiring bound Turnstile to avoid presenting an unsolvable challenge:

  ```caddyfile
  {
      servers {
          protocols h1 h2
          listener_wrappers {
              ja4
              tls
          }
      }
  }
  ```

  This setting is server-wide. Unbound Turnstile remains supported with
  HTTP/3. QUIC-derived JA4 values remain useful for telemetry, but must not
  be trusted as an authorization boundary in `bot_policy` either.
  The HTTP/3 packet parser's state is bounded to avoid memory exhaustion,
  but that is distinct from fingerprint authenticity.
- **PROXY protocol.** If Caddy sits behind a load balancer that speaks the
  PROXY protocol, its header precedes the ClientHello on the wire. The wrapper
  that decodes it must come **before** `ja4` in `listener_wrappers`, or `ja4`
  will see the PROXY header instead of a TLS record and compute nothing.
- **Exact matching.** There are no wildcards or prefix matches.

## About the JA4 implementation

The fingerprint follows the [FoxIO](https://github.com/FoxIO-LLC/ja4)
specification: `a_b_c`, where `a` is human-readable (transport, TLS version,
SNI presence, cipher and extension counts, ALPN), and `b` and `c` are SHA-256
hashes, truncated to 12 characters, of the sorted cipher list and of the
sorted extension list plus the signature algorithms in the order sent.

Details that matter and are easy to get wrong:

- **GREASE** values (RFC 8701) are dropped from every list. They change on
  every connection, so keeping them would give a different fingerprint per
  handshake.
- The **version** comes from the `supported_versions` extension when present,
  not from the `legacy_version` field, which TLS 1.3 froze at `0x0303`.
- **SNI and ALPN are counted** in the extension count in part `a`, but are
  **excluded** from the part `c` hash: they are already represented in `a`,
  and they vary with the site being visited rather than with the client.
- **Signature algorithms are not sorted**: their order is the client's
  preference and carries signal.
- The ALPN code is the first and **last** character of the first protocol
  offered: `http/1.1` gives `h1`, not `ht`.
- A ClientHello split across **several TLS records** is reassembled before
  parsing, rather than fingerprinting a truncated first record.
- Over QUIC the ClientHello is spread across **CRYPTO frames**, often
  several Initial packets and, with Chrome, deliberately shuffled. Frames are
  reassembled by offset before parsing. QUIC versions 1 (RFC 9000) and 2
  (RFC 9369) are supported.

Both transports were checked against FoxIO's own test captures: all 51
QUIC handshakes in them (Chrome among them) produce FoxIO's expected
fingerprint. The QUIC Initial decryption is tested against the sample
packets in RFC 9001 and RFC 9369.

The TCP implementation was also checked against `github.com/matt-/caddy-ja4` on real
handshakes from Go (TLS 1.2 and 1.3, with and without SNI, with and without
ALPN), curl and `openssl s_client`. Both hash parts match in every case. The
two differences found are in the readable part and are bugs in that
implementation: it reports version `13` for a client that only offers TLS 1.2,
and it emits `ht` instead of `h1` for the `http/1.1` ALPN.

## Build

```sh
xcaddy build --with github.com/perennialtech/caddy-bot-policy
```

This is a fork of
[`carbans/caddy-bot-policy`](https://github.com/carbans/caddy-bot-policy)
with its own module path, adding HTTP/3 support. Builds that used the
upstream path need the new one; the Caddy module IDs and config are
unchanged.

The module IDs `caddy.listeners.ja4` and `http.handlers.ja4` are the same ones
used by `github.com/matt-/caddy-ja4`, so **the two plugins cannot be built into
the same binary**: Caddy panics at startup with `module already registered`.
This module replaces it entirely.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

The policy tests exercise the public `http.vars` interface; the Turnstile
tests use a trusted per-request fingerprint fixture, including negative tests
for spoofed public variables. Fingerprint tests start a real listener
and perform real handshakes with Go's TLS client, and with quic-go for
HTTP/3. The Turnstile tests run against a stand-in siteverify server; the
integration tests among them load real Caddyfiles (with `try_files`,
`rewrite`, `handle`, `handle_path`, matchers and a strict CSP) and send real
requests through Caddy's router.

`test/browser/` holds an end-to-end check that drives real Chromium through
the challenge against Cloudflare's live siteverify, using the public testing
keys. It needs Chromium and network access, so it is not part of `go test`
or CI; `run.py` explains how to run it.

## Status

- [x] JA4 over TCP/TLS (listener wrapper + handler)
- [x] Exact matching by JA4 fingerprint
- [x] Per-directive `on_missing_fingerprint` open/closed
- [x] `block-403` action with a block ID
- [x] JA4 over QUIC/HTTP3 (packet conn wrapper)
- [x] Cloudflare Turnstile challenge with a stateless, fingerprint-bindable clearance
- [ ] More actions (e.g. `redirect`, `tarpit`)
- [ ] Partial/prefix fingerprint matching
