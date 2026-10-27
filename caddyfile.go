package botpolicy

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// parseCaddyfile sets up a bot_policy handler from Caddyfile tokens.
//
//	bot_policy {
//		var_name               ja4
//		block                  t13d1517h2_8daaf6152771_b6f405a00624
//		block                  q13d0312h3_55b375c5d22e_cd8dafe46ac5
//		on_missing_fingerprint open
//		action                 block-403
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var bp BotPolicy
	if err := bp.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &bp, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (bp *BotPolicy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr() // no inline args are supported, only a block
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "var_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				bp.VarName = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			case "block":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				bp.Blocked = append(bp.Blocked, args...)

			case "on_missing_fingerprint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				bp.OnMissingFingerprint = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			case "action":
				if !d.NextArg() {
					return d.ArgErr()
				}
				bp.Action = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			default:
				return d.Errf("unrecognized bot_policy subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// parseTurnstileCaddyfile sets up a turnstile handler from Caddyfile tokens.
//
//	turnstile {
//		site_key         <key>
//		secret_key       <key>
//		clearance_key    <at least 32 bytes>
//		clearance_ttl    30d
//		cookie_name      bp_clearance
//		bind_fingerprint [<var_name>]
//		max_pending_verifications 64
//		allow_insecure_cookie  # HTTP-only local development; never production
//	}
func parseTurnstileCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ts Turnstile
	if err := ts.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &ts, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (ts *Turnstile) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			sub := d.Val()
			switch sub {
			case "bind_fingerprint":
				ts.BindFingerprintVar = "ja4_bind"
				if d.NextArg() {
					ts.BindFingerprintVar = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				continue
			case "allow_insecure_cookie":
				if d.NextArg() {
					return d.ArgErr()
				}
				ts.AllowInsecureCookie = true
				continue
			case "site_key", "secret_key", "clearance_key", "clearance_ttl", "cookie_name", "max_pending_verifications":
			default:
				return d.Errf("unrecognized turnstile subdirective '%s'", sub)
			}

			if !d.NextArg() {
				return d.ArgErr()
			}
			val := d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
			switch sub {
			case "site_key":
				ts.SiteKey = val
			case "secret_key":
				ts.SecretKey = val
			case "clearance_key":
				ts.ClearanceKey = val
			case "clearance_ttl":
				dur, err := caddy.ParseDuration(val)
				if err != nil {
					return d.Errf("bad clearance_ttl %q: %v", val, err)
				}
				ts.ClearanceTTL = caddy.Duration(dur)
			case "cookie_name":
				ts.CookieName = val
			case "max_pending_verifications":
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					return d.Errf("max_pending_verifications must be a positive integer, got %q", val)
				}
				ts.MaxPendingVerifications = n
			}
		}
	}
	return nil
}
