package botpolicy

import (
	"os"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func TestExamplesAdapt(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "127.0.0.1/32")
	t.Setenv("BIND", "127.0.0.1:3000")
	t.Setenv("TARGET", "127.0.0.1:8080")
	for _, name := range []string{"examples/turnstile.Caddyfile", "examples/proxy/filter.Caddyfile"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := (caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}).Adapt(data, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
