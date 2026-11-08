package botpolicy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestIntegrationComposablePolicy(t *testing.T) {
	t.Setenv("MONITOR_TOKEN", "monitor-secret")
	db := testASNDatabase(t, "GeoLite2-ASN")
	base := startCaddy(t, `
        @denyIP client_ip 192.0.2.0/24
        @denyUA header_regexp User-Agent BadBot
        @denyASN asn {
            numbers 13335
            asn_db `+db+`
        }
        @allowIP client_ip 198.51.100.0/24
        @allowUA header_regexp User-Agent GoodBot
        @allowASN asn {
            numbers 64500
            asn_db `+db+`
        }
        @monitor secret_header X-Monitor-Token {env.MONITOR_TOKEN}
        route {
            respond @denyIP 403
            respond @denyUA 403
            respond @denyASN 403
            handle @allowIP {
  respond "protected"
}
            handle @allowUA {
 respond "protected"
}
            handle @allowASN {
 respond "protected"
}
            handle @monitor {
 respond "protected"
}
            handle {
                %TURNSTILE%
                respond "protected"
            }
        }
    `, `servers {
trusted_proxies static 127.0.0.1/32
trusted_proxies_strict
}`)
	for _, tc := range []struct {
		name, clientIP, agent, token string
		want                         int
		challenge                    bool
	}{
		{"missing", "", "", "", 403, true},
		{"wrong secret", "", "", "invalid", 403, true},
		{"header alone", "", "", "monitor-secret", 200, false},
		{"IP alternative", "198.51.100.7", "", "", 200, false},
		{"UA alternative", "", "GoodBot", "", 200, false},
		{"ASN alternative", "2001:db8:abcd::7", "", "", 200, false},
		{"blacklisted IP beats secret", "192.0.2.7", "", "monitor-secret", 403, false},
		{"blacklisted UA beats secret", "", "BadBot", "monitor-secret", 403, false},
		{"blacklisted ASN beats secret", "203.0.113.7", "", "monitor-secret", 403, false},
		{"blacklisted ASN beats UA", "203.0.113.7", "GoodBot", "", 403, false},
		{"blacklisted IP beats allowed ASN", "192.0.2.7", "", "", 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
			if tc.clientIP != "" {
				req.Header.Set("X-Forwarded-For", tc.clientIP)
			}
			if tc.agent != "" {
				req.Header.Set("User-Agent", tc.agent)
			}
			if tc.token != "" {
				req.Header.Set("x-monitor-token", tc.token)
			}
			resp, body := newVisitor(t, base).do(req)
			if resp.StatusCode != tc.want || strings.Contains(body, "cf-turnstile") != tc.challenge {
				t.Fatalf("got %d %q, want %d, challenge %v", resp.StatusCode, body, tc.want, tc.challenge)
			}
			if tc.want == 200 && body != "protected" {
				t.Fatalf("got body %q", body)
			}
		})
	}
}

func TestIntegrationSecretPathMethodAndRewrite(t *testing.T) {
	t.Setenv("MONITOR_TOKEN", "monitor-secret")
	base := startCaddy(t, `
        @health {
            path /health
            method GET
            secret_header X-Monitor-Token {env.MONITOR_TOKEN}
        }
        @denyOriginal path /blocked
        route {
            respond @denyOriginal 403
            handle @health {
 respond "health"
}
            handle {
                %TURNSTILE%
                rewrite * /internal
                respond "protected {path}"
            }
        }
    `)
	for _, tc := range []struct {
		path, method, token string
		want                int
		challenge           bool
	}{
		{"/health", "GET", "monitor-secret", 200, false},
		{"/health", "POST", "monitor-secret", 403, true},
		{"/other", "GET", "monitor-secret", 403, true},
		{"/blocked", "GET", "monitor-secret", 403, false},
	} {
		req, _ := http.NewRequest(tc.method, base+tc.path, nil)
		req.Header.Set("X-Monitor-Token", tc.token)
		resp, body := newVisitor(t, base).do(req)
		if resp.StatusCode != tc.want || strings.Contains(body, "cf-turnstile") != tc.challenge {
			t.Errorf("%s %s: got %d %q, want %d challenge %v", tc.method, tc.path, resp.StatusCode, body, tc.want, tc.challenge)
		}
	}
}

func TestASNMatcherNegationInEarlyData(t *testing.T) {
	m := parseASNMatcher(t, testASNDatabase(t, "GeoLite2-ASN"), 13335)
	not := caddyhttp.MatchNot{MatcherSets: caddyhttp.MatcherSets{{m}}}
	req := newTurnstileRequest(http.MethodGet, "https://"+testHost+"/", nil)
	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, "203.0.113.7")
	req.TLS.HandshakeComplete = false
	matched, err := not.MatchWithError(req)
	if matched || err == nil {
		t.Fatalf("unsafe early-data negation: match %v, error %v", matched, err)
	}
}
