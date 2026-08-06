# caddy-bot-policy

Plugin de [Caddy](https://caddyserver.com) que calcula la huella TLS de cliente
**JA4** y bloquea peticiones cuya huella esté en una lista de bloqueo.

El módulo aporta tres piezas:

| Módulo | Qué hace |
|---|---|
| `caddy.listeners.ja4` | Listener wrapper: lee el ClientHello en crudo y calcula el JA4 |
| `http.handlers.ja4` | Publica esa huella en una variable de petición |
| `http.handlers.bot_policy` | Bloquea las peticiones cuya huella esté en la lista |

Están separados porque el JA4 **solo puede calcularse antes de terminar el
TLS** — una vez completado el handshake el ClientHello ya no existe, y
`tls.ConnectionState` de Go solo expone el resultado negociado, no las listas
de ciphers y extensiones ofrecidas de las que se construye la huella. La
política, en cambio, solo puede aplicarse cuando ya hay una petición HTTP
parseada. Las dos mitades se comunican a través de una variable, lo que además
deja la huella disponible para `log_append` y para los matchers de Caddy.

## Configuración

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

**El wrapper `ja4` tiene que ir antes que `tls`** en `listener_wrappers`: es
justo lo que le permite ver el handshake sin cifrar.

Las directivas `ja4` y `bot_policy` se auto-ordenan (`ja4` primero), así que no
hacen falta líneas `order` globales salvo que convivan con otras directivas de
terceros que necesiten un orden concreto.

### Solo observar, sin bloquear

`ja4` funciona por su cuenta. Es la forma sensata de empezar: publicas la
huella, la vuelcas al log y construyes la lista de bloqueo con datos reales
antes de bloquear nada.

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

### Subdirectivas de `ja4`

| Subdirectiva | Valores | Descripción |
|---|---|---|
| `var_name` | nombre de variable (por defecto `ja4`) | Clave `http.vars.*` donde se publica la huella. |

### Opciones del listener wrapper

| Opción | Valores | Descripción |
|---|---|---|
| `max_capture_bytes` | entero (por defecto `16384`) | Cuántos bytes puede bufferear como máximo esperando al ClientHello. Un registro TLS no pasa de 16 KiB; los hellos con claves post-cuánticas ya superan los 2 KiB. |

### Subdirectivas de `bot_policy`

| Subdirectiva | Valores | Descripción |
|---|---|---|
| `var_name` | nombre de variable (por defecto `ja4`) | Debe coincidir con el `var_name` de la directiva `ja4`. |
| `block` | huella JA4 | Repetible; admite varios valores en la misma línea. Se requiere al menos una. |
| `on_missing_fingerprint` | `open` \| `closed` (por defecto `open`) | Qué hacer cuando no hay huella: sin TLS, sobre HTTP/3, o un ClientHello ilegible. `open` deja pasar, `closed` bloquea. |
| `action` | `block-403` (único valor soportado) | 403 + cabecera `X-Block-Id` con identificador único (prefijo `bp-`, distinto del `np-` de `network_policy`) y log de la petición bloqueada. |

## Limitaciones

- **HTTP/3 no se huella.** Los listener wrappers de Caddy solo envuelven
  listeners TCP; en QUIC el ClientHello viaja dentro de paquetes Initial. Las
  peticiones que llegan por h3 alcanzan `bot_policy` con la variable vacía y se
  resuelven por `on_missing_fingerprint`.
- **PROXY protocol.** Si Caddy está detrás de un balanceador que habla PROXY
  protocol, su cabecera va por delante del ClientHello en el cable. El wrapper
  que la decodifica tiene que ir **antes** que `ja4` en `listener_wrappers`, o
  `ja4` verá la cabecera PROXY en lugar de un registro TLS y no calculará nada.
- **Coincidencia exacta.** No hay comodines ni coincidencia por prefijo.

## Sobre la implementación de JA4

El fingerprint sigue la especificación de
[FoxIO](https://github.com/FoxIO-LLC/ja4): `a_b_c`, donde `a` es legible
(transporte, versión TLS, presencia de SNI, número de ciphers y extensiones,
ALPN), y `b` y `c` son SHA-256 truncados a 12 caracteres de la lista ordenada
de ciphers y de la lista ordenada de extensiones más los algoritmos de firma en
orden de emisión.

Detalles que importan y son fáciles de equivocar:

- Los valores **GREASE** (RFC 8701) se descartan de todas las listas. Varían en
  cada conexión, así que dejarlos daría una huella distinta por handshake.
- La **versión** se toma de la extensión `supported_versions` cuando está
  presente, no del campo `legacy_version`, que TLS 1.3 congeló en `0x0303`.
- **SNI y ALPN se cuentan** en el número de extensiones de la parte `a` pero se
  **excluyen** del hash de la parte `c`: ya están representados ahí, y varían
  según el sitio visitado en lugar de según el cliente.
- Los **algoritmos de firma no se ordenan**: su orden es preferencia del
  cliente y lleva señal.
- El código ALPN son el primer y **último** carácter del primer protocolo
  ofrecido — `http/1.1` da `h1`, no `ht`.

La implementación se contrastó contra `github.com/matt-/caddy-ja4` sobre
handshakes reales de Go (TLS 1.2 y 1.3, con y sin SNI, con y sin ALPN), curl y
`openssl s_client`. Las dos partes hash coinciden en todos los casos. Las dos
diferencias encontradas están en la parte legible y son fallos de aquella
implementación: reporta versión `13` para un cliente que solo ofrece TLS 1.2, y
emite `ht` en lugar de `h1` para ALPN `http/1.1`.

## Build

```sh
xcaddy build --with github.com/carbans/caddy-bot-policy
```

Los IDs de módulo `caddy.listeners.ja4` y `http.handlers.ja4` son los mismos que
usa `github.com/matt-/caddy-ja4`, así que **los dos plugins no pueden convivir
en el mismo binario**: Caddy entra en pánico al arrancar con
`module already registered`. Este módulo lo sustituye por completo.

## Desarrollo

```sh
go build ./...
go vet ./...
go test ./...
```

Los tests de política inyectan la huella directamente vía
`caddyhttp.SetVar`/`VarsCtxKey`; los del fingerprint levantan un listener real y
hacen handshakes de verdad con el cliente TLS de Go.

## Estado

- [x] Cálculo de JA4 sobre TCP/TLS (listener wrapper + handler)
- [x] Coincidencia exacta por huella JA4
- [x] `on_missing_fingerprint` open/closed por directiva
- [x] Acción `block-403` con ID de bloqueo
- [ ] JA4 sobre QUIC/HTTP3
- [ ] Soporte de más acciones (p.ej. `redirect`, `tarpit`)
- [ ] Coincidencia parcial/por prefijo de huella
