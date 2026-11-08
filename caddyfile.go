package botpolicy

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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
