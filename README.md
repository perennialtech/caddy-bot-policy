# caddy-bot-policy

A [Caddy](https://caddyserver.com) module for whitelisting and
blacklisting client IPs, CIDRs, User-Agent patterns and ASNs, and issuing
[Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)
challenge clearances.

## Install

Build Caddy with the plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build v2.11.9 --with github.com/perennialtech/caddy-bot-policy
```

## Configure policies and challenges

Start with [examples/turnstile.Caddyfile](examples/turnstile.Caddyfile).
Replace the example entries and upstream, and supply
`TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`.

- `bot_policy` accepts IPv4/IPv6 addresses, CIDRs,
  `ua:`-prefixed Go regular expressions (RE2), and `asn:`-prefixed AS
  numbers in its `whitelist` and `blacklist` lists.
  For example, `blacklist "ua:(?i)badbot"` matches `BadBot/1.0`.
  User-Agent patterns match substrings and are case-sensitive unless
  they use `(?i)`; use `^` and `$` for full-string matches. Missing
  User-Agent headers never match. Quote expressions containing spaces.
  User-Agent is client-controlled and should not be used for authentication.
  Blacklist matches receive a 403; otherwise whitelist matches bypass
  Turnstile.
- `turnstile` serves a challenge until the client presents a signed
  clearance. Supply site and secret keys for your hostname. Cloudflare
  does not need to proxy your site.

The canonical configuration reference is the Caddyfile parser in
[caddyfile.go](caddyfile.go) and the option comments in
[policy.go](policy.go) and [turnstile.go](turnstile.go).

The `bot_policy` and `turnstile` directives run ahead of
`rewrite` and `try_files` unless you place them in a `route`, whose
order is explicit. Path-scoped Turnstile policies match the original
requested URL; protect any public rewrite aliases as well. For
method-restricted matchers, include both GET and POST. Use matchers to
exclude webhook, API and preflight paths rather than challenging them.

For `asn:13335` entries in either list, you can use an automatically
managed [MaxMind GeoLite2 ASN database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).
Supply your MaxMind account ID and license key:

```caddyfile
bot_policy {
    asn_db maxmind {
        account_id  {env.MAXMIND_ACCOUNT_ID}
        license_key {env.MAXMIND_LICENSE_KEY}
    }
    blacklist asn:13335
}
```

Caddy downloads the database on first start, caches it in its data
directory, checks for updated builds daily, and swaps in new data without
reloading. If a cached copy exists, startup does not wait for MaxMind;
failed updates keep the cached database in service.

Alternatively, obtain a local GeoLite2, GeoIP2 ASN, or
[DB-IP ASN Lite database](https://db-ip.com/db/download/ip-to-asn-lite),
and set `asn_db /path/to/asn.mmdb` in `bot_policy`. Replace the file
atomically (write a temporary file, then rename it into place); Caddy
picks up changes within a minute without a config reload. Failed
updates keep the last valid database. Requests never perform external
ASN lookups. Lookups use Caddy's resolved client IP (respecting
`trusted_proxies`), not forwarding headers. Unknown or unmapped IPs
have no ASN match; ASN rules require a readable database at startup.

## Operational requirements

**Protect challenge responses and verification requests.**
Match Turnstile on both GET and POST: the verification form posts to the
challenged URL, then redirects to it with GET. Rewrites, GET-only
matchers and routes must admit the verification POST. Protect the
siteverify endpoint from excessive submissions with an appropriate
upstream rate limit. Deferred response headers must not override the
challenge page's CSP or `Cache-Control: no-store`.

**Do not share-cache cleared pages without enforcing the same policy.**
A CDN or reverse proxy in front of Caddy can otherwise serve a protected
response to a client without clearance. Disable shared caching for
protected paths, or enforce clearance at that cache.

**Account for non-browser traffic.** Webhooks, health checks, cross-origin
OPTIONS preflights, and clients without JavaScript cannot solve the widget;
exclude appropriate paths using matchers. Challenging a POST loses its
body after the verification redirect. Public HTTPS is required for secure
cookies, including when TLS terminates at an upstream proxy.

## Development and testing

Run the gates defined in [.github/workflows/ci.yml](.github/workflows/ci.yml).

`test/browser/` contains an optional browser integration test against
Cloudflare's public Turnstile testing keys. Its `run.py` explains the
additional dependencies; it is not part of CI.
