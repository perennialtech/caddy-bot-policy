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
//		asn_db                 /var/lib/geoip/GeoLite2-ASN.mmdb
//		// Or: asn_db maxmind {
//		//     account_id  {env.MAXMIND_ACCOUNT_ID}
//		//     license_key {env.MAXMIND_LICENSE_KEY}
//		// }
//		whitelist              192.0.2.10 2001:db8:1::/48 "ua:(?i)googlebot"
//		whitelist              asn:13335
//		blacklist              198.51.100.0/24
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
			case "asn_db":
				if !d.NextArg() {
					return d.ArgErr()
				}
				value := d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
				if bp.ASNDB != "" || bp.MaxMind != nil {
					return d.Err("asn_db may only be configured once")
				}
				if value == "maxmind" {
					bp.MaxMind = &MaxMindASN{}
					for d.NextBlock(1) {
						key := d.Val()
						switch key {
						case "account_id", "license_key":
						default:
							return d.Errf("unknown maxmind option %q", key)
						}
						if !d.NextArg() {
							return d.ArgErr()
						}
						arg := d.Val()
						if d.NextArg() {
							return d.ArgErr()
						}
						if key == "account_id" {
							bp.MaxMind.AccountID = arg
						} else {
							bp.MaxMind.LicenseKey = arg
						}
					}
					if bp.MaxMind.AccountID == "" || bp.MaxMind.LicenseKey == "" {
						return d.Err("maxmind requires account_id and license_key")
					}
				} else {
					bp.ASNDB = value
				}

			case "whitelist", "blacklist":
				sub := d.Val()
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				if sub == "whitelist" {
					bp.Whitelist = append(bp.Whitelist, args...)
				} else {
					bp.Blacklist = append(bp.Blacklist, args...)
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
