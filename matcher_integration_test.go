package turnstile

import (
	"net/http"
	"strings"
	"testing"
)

func TestIntegrationComposablePolicy(t *testing.T) {
	base := startCaddy(t, `
        @denyIP client_ip 192.0.2.0/24
        @denyUA header_regexp User-Agent BadBot
        @allowIP client_ip 198.51.100.0/24
        @allowUA header_regexp User-Agent GoodBot
        route {
            respond @denyIP 403
            respond @denyUA 403
            handle @allowIP {
                respond "protected"
            }
            handle @allowUA {
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
		name, clientIP, agent string
		want                  int
		challenge             bool
	}{
		{"missing", "", "", 403, true},
		{"IP alternative", "198.51.100.7", "", 200, false},
		{"UA alternative", "", "GoodBot", 200, false},
		{"blacklisted IP beats allowed UA", "192.0.2.7", "GoodBot", 403, false},
		{"blacklisted UA beats allowed IP", "198.51.100.7", "BadBot", 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
			if tc.clientIP != "" {
				req.Header.Set("X-Forwarded-For", tc.clientIP)
			}
			if tc.agent != "" {
				req.Header.Set("User-Agent", tc.agent)
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

func TestIntegrationPathMethodAndRewrite(t *testing.T) {
	base := startCaddy(t, `
        @health {
            path /health
            method GET
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
		path, method string
		want         int
		challenge    bool
	}{
		{"/health", "GET", 200, false},
		{"/health", "POST", 403, true},
		{"/other", "GET", 403, true},
		{"/blocked", "GET", 403, false},
	} {
		req, _ := http.NewRequest(tc.method, base+tc.path, nil)
		resp, body := newVisitor(t, base).do(req)
		if resp.StatusCode != tc.want || strings.Contains(body, "cf-turnstile") != tc.challenge {
			t.Errorf("%s %s: got %d %q, want %d challenge %v", tc.method, tc.path, resp.StatusCode, body, tc.want, tc.challenge)
		}
	}
}
