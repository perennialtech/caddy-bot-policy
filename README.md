# caddy-bot-policy

A [Caddy](https://caddyserver.com) module providing ASN and secret-header
request matchers plus [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
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
`TURNSTILE_SECRET_KEY`, and `MONITOR_TOKEN`.

The previous `bot_policy` directive has been removed. To migrate:

- Replace IP and CIDR rules with Caddy's `client_ip` matcher, and
  `ua:` regular expressions with `header_regexp User-Agent`.
- Replace `asn:` rules with named `asn` matchers. Each matcher takes a
  `numbers` list and an `asn_db` source (a local file or `maxmind` block).
- Replace trusted-monitor rules with `secret_header <name> <secret>`.
  Placeholders including `{env.*}` resolve once during provisioning.
- Replace `blacklist` rules with `respond` matches at the top of a `route`.
  Use separate `respond` directives for each alternative. Put them before
  any allow routes so that a blacklist match wins even for a cleared client.
- Replace each `whitelist` alternative with a separate `handle` matching
  that condition and going directly to the upstream. These handles are
  mutually exclusive with the final fallback `handle` containing `turnstile`
  and the upstream. Putting different matcher types in one named matcher
  combines them with AND, **not** OR. Use separate handles for OR, or combine
  matchers deliberately to require multiple conditions.

The complete example also shows evaluation before rewrites: explicit `route`
order is authoritative. Do not put rewrites ahead of the policy decisions.
Use `path` and `method` matchers to scope checks; a Turnstile-protected
page needs GET and POST for verification.

`asn` uses Caddy's resolved client IP, including its `trusted_proxies`
configuration, not the raw `X-Forwarded-For` header. An ASN matcher returns
HTTP 425 during an incomplete TLS handshake rather than treating an unsafe
0-RTT lookup as a nonmatch; this remains safe even when negated with `not`.
Caddy's `client_ip` matcher also returns HTTP 425 in 0-RTT. An unmapped IP
or a different ASN is a normal nonmatch. A failed lookup returns an error.

`secret_header` validates the header name and rejects an empty secret,
including an unset environment placeholder. It compares every supplied
header value exactly, in constant time, with a case-insensitive header name.
Unlike `header`, it has no wildcard semantics. **Keep the secret out of
access logs:** Caddy records custom request headers in plain text by default.
`Cookie`, `Set-Cookie`, `Authorization`, and `Proxy-Authorization` are redacted
by default unless `log_credentials` is enabled. Use Caddy's log filtering for
custom credentials, or send a secret through `Authorization` instead. These
headers are also forwarded to the upstream unless removed: place
`request_header -X-Monitor-Token` after the matching decision and before
`reverse_proxy`, as in the example. Never use User-Agent matching as
authentication; the client controls it.

The `turnstile` handler still serves challenges until the client presents a
signed clearance. Supply keys for your hostname; Cloudflare does not need
to proxy the site. The canonical option references are the Caddyfile parser
in [caddyfile.go](caddyfile.go), the matcher types in
[asn_matcher.go](asn_matcher.go) and [secret_header.go](secret_header.go),
and the handler options in [turnstile.go](turnstile.go).

### ASN database management

Use managed MaxMind GeoLite2 ASN data by placing this inside an `asn` matcher:

```caddyfile
asn_db maxmind {
    account_id {env.MAXMIND_ACCOUNT_ID}
    license_key {env.MAXMIND_LICENSE_KEY}
}
```

Caddy downloads the database on first start, caches it in its existing data
directory, checks for updated builds daily, and swaps in new data without
reloading. If a cached copy exists, startup does not wait for MaxMind;
failed updates keep the cached data in service.

Alternatively, use a local GeoLite2, GeoIP2 ASN, or
[DB-IP ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite) MMDB with
`asn_db /path/to/asn.mmdb` inside the matcher. Replace that file atomically;
Caddy detects the replacement within a minute without reloading its config.
Shared file watchers and MaxMind refreshers remain shared across matchers.
Unknown or unmapped IPs do not match. A usable database is required at start.

### Native blocking differences

With `respond @blocked 403`, Caddy returns a normal 403 response. The old
`bot_policy`-specific `bp-` block ID, `X-Block-Id` response header, block
log message and automatic `Cache-Control: no-store` header are no longer
provided by the plugin. Add Caddy `header` rules (for example,
`header @blocked Cache-Control no-store`) and request logging if needed.
Turnstile verification errors still have their own `ts-` block IDs.

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
