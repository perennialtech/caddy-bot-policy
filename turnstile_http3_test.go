package botpolicy

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// loadHTTP3Caddy loads an HTTP/3-only Caddy config for https://example.com
// on port, with the ja4 packet conn wrapper and site as the site body. dir
// holds Caddy's storage and the certificate.
func loadHTTP3Caddy(t *testing.T, dir string, port int, site string) {
	t.Helper()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certFile); err != nil {
		cert := selfSignedCert(t)
		key, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
		os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), 0o600)
	}
	cfg := fmt.Sprintf(`{
	admin off
	persist_config off
	auto_https disable_redirects
	storage file_system %s
	https_port %d
	servers {
		protocols h3
		packet_conn_wrappers {
			ja4
		}
	}
}

https://example.com:%d {
	tls %s %s
	ja4
%s
	respond "{http.vars.ja4} {http.vars.ja4_bind}"
}
`, dir, port, port, certFile, keyFile, site)
	adapted, _, err := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}.Adapt([]byte(cfg), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v\n%s", err, cfg)
	}
	if err := caddy.Load(adapted, true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
}

// h3Visitor is a visitor speaking HTTP/3 that resumes TLS sessions and
// remembers the QUIC connections it dialed.
type h3Visitor struct {
	*visitor
	transport *http3.Transport

	mu    sync.Mutex
	conns []*quic.Conn
}

func newH3Visitor(t *testing.T, base string) *h3Visitor {
	v := &h3Visitor{}
	v.transport = &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(4),
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort("127.0.0.1", port), tlsCfg, cfg)
			if err == nil {
				v.mu.Lock()
				v.conns = append(v.conns, conn)
				v.mu.Unlock()
			}
			return conn, err
		},
	}
	t.Cleanup(func() { v.transport.Close() })
	v.visitor = &visitor{t: t, base: base, client: &http.Client{
		Timeout:       10 * time.Second,
		Transport:     v.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	return v
}

// reconnect drops the current QUIC connection so the next request dials a
// new one, resuming the TLS session.
func (v *h3Visitor) reconnect() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.conns {
		c.CloseWithError(0, "")
	}
	v.transport.CloseIdleConnections()
}

func (v *h3Visitor) lastConn() *quic.Conn {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.conns[len(v.conns)-1]
}

// TestTurnstileBoundClearanceOverHTTP3 runs a bound Turnstile challenge
// through Caddy over real HTTP/3, so the fingerprint comes from the QUIC
// handshake hook rather than a populated table. The clearance must keep
// working on a resumed connection and on a 0-RTT request, and bot_policy
// must see the same fingerprint.
func TestTurnstileBoundClearanceOverHTTP3(t *testing.T) {
	newFake(t, testHost, turnstileAction)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	dir := t.TempDir()
	turnstile := `	turnstile {
		site_key         ` + testSiteKey + `
		secret_key       ` + testSecretKey + `
		bind_fingerprint ja4_bind
	}`
	loadHTTP3Caddy(t, dir, port, turnstile)
	t.Cleanup(func() { _ = caddy.Stop() })

	v := newH3Visitor(t, fmt.Sprintf("https://%s:%d", testHost, port))
	exact, bind, ok := strings.Cut(v.pass("/"), " ")
	if !ok || !strings.HasPrefix(exact, "q13d") || !strings.HasPrefix(bind, "q13d") {
		t.Fatalf("HTTP/3 fingerprints %q %q, want QUIC JA4s", exact, bind)
	}

	// A new connection resumes the TLS session: pre_shared_key changes the
	// exact JA4 but not the bind fingerprint, so the clearance still holds.
	v.reconnect()
	resp, body := v.get("/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resumed connection: got %d, want the cleared page", resp.StatusCode)
	}
	if !v.lastConn().ConnectionState().TLS.DidResume {
		t.Fatal("second connection did not resume the TLS session")
	}
	resumedExact, resumedBind, _ := strings.Cut(body, " ")
	if resumedBind != bind || resumedExact == exact {
		t.Fatalf("resumed fingerprints %q %q; want bind %q and an exact JA4 other than %q", resumedExact, resumedBind, bind, exact)
	}

	// 0-RTT data is protected by keys derived from this connection's
	// ClientHello, so its requests carry the same fingerprint.
	v.reconnect()
	req, _ := http.NewRequest(http3.MethodGet0RTT, v.base+"/", nil)
	resp, body = v.do(req)
	if resp.StatusCode != http.StatusOK || !strings.HasSuffix(body, " "+bind) {
		t.Fatalf("0-RTT request: got %d %q, want the cleared page with bind %q", resp.StatusCode, body, bind)
	}
	if !v.lastConn().ConnectionState().Used0RTT {
		t.Fatal("third connection did not use 0-RTT")
	}

	// bot_policy blocks the HTTP/3 fingerprint the handshake produced. The
	// reload keeps the pooled QUIC listener, and with it the hook. A new
	// visitor has no session to resume, so it sends the first hello again.
	loadHTTP3Caddy(t, dir, port, "\tbot_policy {\n\t\tblock "+exact+"\n\t}")
	if resp, body := newH3Visitor(t, v.base).get("/"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bot_policy: got %d %q for blocked JA4 %s, want 403", resp.StatusCode, body, exact)
	}
}
