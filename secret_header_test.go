package botpolicy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestSecretHeaderMatches(t *testing.T) {
	t.Setenv("MONITOR_TOKEN", "a=b=c")
	m := &MatchSecretHeader{Name: "x-monitor-token", Value: "{env.MONITOR_TOKEN}"}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"matching", []string{"a=b=c"}, true},
		{"wrong", []string{"a=b"}, false},
		{"missing", nil, false},
		{"empty", []string{""}, false},
		{"multiple", []string{"wrong", "a=b=c"}, true},
		{"prefix only", []string{"a=b=c-extra"}, false},
		{"wildcard is literal", []string{"a*=c"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
			for _, value := range tc.values {
				req.Header.Add("X-MONITOR-TOKEN", value)
			}
			if got := m.Match(req); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if m.Name != "X-Monitor-Token" {
		t.Fatalf("name is not canonical: %q", m.Name)
	}
	t.Setenv("MONITOR_TOKEN", "different")
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("x-monitor-token", "a=b=c")
	if !m.Match(req) {
		t.Fatal("secret changed after provisioning")
	}
}

func TestSecretHeaderRejectsUnsafeConfig(t *testing.T) {
	t.Setenv("NO_MONITOR_TOKEN", "")
	for _, tc := range []struct{ name, value string }{
		{"", "secret"},
		{"bad:name", "secret"},
		{"has space", "secret"},
		{"x-token", ""},
		{"x-token", "{env.NO_MONITOR_TOKEN}"},
	} {
		m := &MatchSecretHeader{Name: tc.name, Value: tc.value}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Errorf("accepted invalid name or secret")
		} else if strings.Contains(err.Error(), tc.value) && len(tc.value) > 15 {
			t.Errorf("secret leaked through error: %s", err)
		}
	}
}

func TestSecretHeaderCaddyfile(t *testing.T) {
	for _, tt := range []struct {
		text    string
		wantErr bool
	}{
		{"secret_header X-Monitor-Token {env.MONITOR_TOKEN}", false},
		{"secret_header X-Monitor-Token foo=bar", false},
		{"secret_header X-Monitor-Token", true},
		{"secret_header X-Monitor-Token secret extra", true},
	} {
		m := new(MatchSecretHeader)
		if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tt.text)); (err != nil) != tt.wantErr {
			t.Errorf("parse %q: error %v, wantErr %v", tt.text, err, tt.wantErr)
		}
	}
}
