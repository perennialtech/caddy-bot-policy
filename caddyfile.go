package botpolicy

import (
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
