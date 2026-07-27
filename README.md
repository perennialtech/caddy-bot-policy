# caddy-bot-policy

Plugin de [Caddy](https://caddyserver.com) que bloquea peticiones cuya huella
TLS de cliente (JA4) esté en una lista de bloqueo. La huella no la calcula
este módulo: se lee de una variable de petición que deja establecida
previamente en el pipeline un módulo de fingerprinting como
[`github.com/matt-/caddy-ja4`](https://github.com/matt-/caddy-ja4)
(`caddy.listeners.ja4` + `http.handlers.ja4`).

## Directiva `bot_policy`

```caddyfile
example.com {
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

> Nota: la sintaxis anterior es la real de Caddyfile (bloque de subdirectivas
> separadas por espacios). Caddyfile no admite listas estilo YAML
> (`block: [ ... ]`); ese formato solo sirve como boceto de especificación.

### Subdirectivas

| Subdirectiva             | Valores                              | Descripción |
|---------------------------|---------------------------------------|--------------|
| `var_name`                 | nombre de variable (por defecto `ja4`) | Clave `http.vars.*` donde el módulo `ja4` deja la huella calculada. Debe coincidir con el `var_name` con el que se configuró ese módulo en el mismo pipeline de la petición. |
| `block`                     | huella JA4                            | Repetible; puede darse varios valores en la misma línea. Lista exacta de huellas bloqueadas. Se requiere al menos una. |
| `on_missing_fingerprint`   | `open` \| `closed` (por defecto `open`) | Qué hacer cuando la variable configurada en `var_name` está vacía o no existe (sin TLS, módulo `ja4` no configurado en el pipeline, etc.). `open` deja pasar la petición; `closed` la bloquea. |
| `action`                    | `block-403` (único valor soportado)  | Respuesta al bloquear: 403 + cabecera `X-Block-Id` con un identificador único para trazabilidad/soporte, y log de la petición bloqueada. |

### Semántica de bloqueo

1. Se lee la huella JA4 de `http.vars.<var_name>` (por defecto
   `http.vars.ja4`), establecida por un módulo de fingerprinting anterior en
   el pipeline.
2. Si la variable está vacía o no existe, el resultado se resuelve con
   `on_missing_fingerprint`.
3. Si la variable tiene valor, se bloquea si y solo si coincide exactamente
   con alguna entrada de `block`.

### Orden de directivas

Este módulo se auto-registra con
`httpcaddyfile.RegisterDirectiveOrder("bot_policy", httpcaddyfile.Before, "basicauth")`,
igual que `network_policy`. Eso basta para ordenarlo frente a las directivas
estándar de Caddy, pero **no** frente a otras directivas de terceros como
`ja4` o `waf`: para garantizar que `bot_policy` se evalúa después de que
`ja4` haya calculado la huella, el Caddyfile consumidor necesita además una
línea global explícita, p.ej.:

```caddyfile
{
	order ja4 first
	order bot_policy after ja4
}
```

Esa línea `order` vive en la configuración que genera waf-api, no en este
repositorio.

## Build

Este repositorio es un módulo Go pensado para compilarse dentro de un binario
de Caddy con [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/carbans/caddy-bot-policy=.
```

## Desarrollo

```sh
go build ./...
go vet ./...
go test ./...
```

Los tests unitarios no requieren un módulo `ja4` real: la huella se inyecta
directamente en el contexto de la petición vía `caddyhttp.SetVar`/`VarsCtxKey`.

## Estado

- [x] Coincidencia exacta por huella JA4
- [x] `on_missing_fingerprint` open/closed por directiva
- [x] Acción `block-403` con ID de bloqueo (prefijo `bp-`, distinto del `np-`
      de `network_policy`, para diferenciar el origen del bloqueo en logs)
- [ ] Soporte de más acciones (p.ej. `redirect`, `tarpit`)
- [ ] Coincidencia parcial/por prefijo de huella
