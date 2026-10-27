# caddy-bot-policy

A [Caddy](https://caddyserver.com) plugin that computes the **JA4** TLS client
fingerprint and blocks requests whose fingerprint is on a blocklist.

The plugin provides three modules:

| Module | What it does |
|---|---|
| `caddy.listeners.ja4` | Listener wrapper: reads the raw ClientHello and computes the JA4 |
| `http.handlers.ja4` | Publishes that fingerprint as a request variable |
| `http.handlers.bot_policy` | Blocks requests whose fingerprint is on the list |

They are separate because a JA4 **can only be computed before TLS is
terminated**. Once the handshake completes the ClientHello is gone, and Go's
`tls.ConnectionState` only exposes the negotiated result, not the offered
cipher and extension lists the fingerprint is built from. A policy, on the
other hand, can only be applied once there is a parsed HTTP request. The two
halves talk through a request variable, which also makes the fingerprint
available to `log_append` and to Caddy's request matchers.

## Configuration

```caddyfile
{
	servers {
		listener_wrappers {
			ja4
			tls
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

The `ja4` and `bot_policy` directives order themselves (`ja4` first), so no
global `order` lines are needed unless they share a route with other
third-party directives that need a specific order.

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

### `ja4` subdirectives

| Subdirective | Values | Description |
|---|---|---|
| `var_name` | variable name (default `ja4`) | The `http.vars.*` key the fingerprint is published under. |

### Listener wrapper options

| Option | Values | Description |
|---|---|---|
| `max_capture_bytes` | integer (default `16384`) | The most bytes that may be buffered while waiting for the ClientHello. A single TLS record tops out at 16 KiB; hellos carrying post-quantum key shares already exceed 2 KiB. |

### `bot_policy` subdirectives

| Subdirective | Values | Description |
|---|---|---|
| `var_name` | variable name (default `ja4`) | Must match the `var_name` of the `ja4` directive. |
| `block` | JA4 fingerprint | Repeatable; several values may be given on one line. At least one is required. |
| `on_missing_fingerprint` | `open` \| `closed` (default `open`) | What to do when there is no fingerprint: no TLS, HTTP/3, or an unreadable ClientHello. `open` lets the request through, `closed` blocks it. |
| `action` | `block-403` (the only supported value) | Responds 403 with an `X-Block-Id` header carrying a unique ID (prefixed `bp-`, distinct from `network_policy`'s `np-`) and logs the blocked request. |

## Limitations

- **HTTP/3 is not fingerprinted.** Caddy's listener wrappers only wrap TCP
  listeners; over QUIC the ClientHello travels inside Initial packets.
  Requests arriving over h3 reach `bot_policy` with an empty variable and are
  resolved by `on_missing_fingerprint`.
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

The implementation was checked against `github.com/matt-/caddy-ja4` on real
handshakes from Go (TLS 1.2 and 1.3, with and without SNI, with and without
ALPN), curl and `openssl s_client`. Both hash parts match in every case. The
two differences found are in the readable part and are bugs in that
implementation: it reports version `13` for a client that only offers TLS 1.2,
and it emits `ht` instead of `h1` for the `http/1.1` ALPN.

## Build

```sh
xcaddy build --with github.com/carbans/caddy-bot-policy
```

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

The policy tests inject the fingerprint directly through
`caddyhttp.SetVar`/`VarsCtxKey`; the fingerprint tests start a real listener
and perform real handshakes with Go's TLS client.

## Status

- [x] JA4 over TCP/TLS (listener wrapper + handler)
- [x] Exact matching by JA4 fingerprint
- [x] Per-directive `on_missing_fingerprint` open/closed
- [x] `block-403` action with a block ID
- [ ] JA4 over QUIC/HTTP3
- [ ] More actions (e.g. `redirect`, `tarpit`)
- [ ] Partial/prefix fingerprint matching
