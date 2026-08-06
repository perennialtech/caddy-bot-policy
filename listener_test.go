package botpolicy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// TestListenerFingerprintsRealHandshake is the test that matters: it runs a
// genuine TLS handshake from Go's own client through the wrapper and checks
// that a fingerprint comes out the far side. Everything else in this package
// works on bytes we made up ourselves.
func TestListenerFingerprintsRealHandshake(t *testing.T) {
	server, clientConn := handshake(t, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
	})
	defer server.close()

	key := normalizeAddr(clientConn.LocalAddr().String())
	fingerprint := conns.get(key)
	if fingerprint == "" {
		t.Fatal("no fingerprint recorded for the connection")
	}

	parts := strings.Split(fingerprint, "_")
	if len(parts) != 3 {
		t.Fatalf("fingerprint %q does not have three parts", fingerprint)
	}
	if len(parts[0]) != 10 {
		t.Errorf("fingerprint %q: part a is %d chars, want 10", fingerprint, len(parts[0]))
	}
	if len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("fingerprint %q: hash parts must be 12 chars each", fingerprint)
	}

	// t = TCP, 13 = TLS 1.3, d = the client sent SNI, and the last two
	// characters come from the first ALPN protocol offered ("h2").
	if got, want := parts[0][:4], "t13d"; got != want {
		t.Errorf("fingerprint %q starts with %q, want %q", fingerprint, got, want)
	}
	if got, want := parts[0][8:], "h2"; got != want {
		t.Errorf("fingerprint %q ends part a with %q, want %q", fingerprint, got, want)
	}

	// Go's client is deterministic enough that a second handshake with the
	// same config must produce the same fingerprint — that is the whole point
	// of dropping GREASE and sorting the lists.
	server2, clientConn2 := handshake(t, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
	})
	defer server2.close()

	if second := conns.get(normalizeAddr(clientConn2.LocalAddr().String())); second != fingerprint {
		t.Errorf("second handshake produced %q, want %q — fingerprint is not stable", second, fingerprint)
	}
}

// TestListenerFingerprintVariesWithClient checks the fingerprint actually
// discriminates: a client offering a different ALPN and TLS version must not
// land on the same value.
func TestListenerFingerprintVariesWithClient(t *testing.T) {
	server, conn := handshake(t, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS13,
	})
	defer server.close()
	withH2 := conns.get(normalizeAddr(conn.LocalAddr().String()))

	server2, conn2 := handshake(t, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		NextProtos:         []string{"http/1.1"},
		MaxVersion:         tls.VersionTLS12,
	})
	defer server2.close()
	withHTTP11 := conns.get(normalizeAddr(conn2.LocalAddr().String()))

	if withH2 == "" || withHTTP11 == "" {
		t.Fatalf("missing fingerprint: h2=%q http/1.1=%q", withH2, withHTTP11)
	}
	if withH2 == withHTTP11 {
		t.Errorf("two very different clients produced the same fingerprint %q", withH2)
	}
	if !strings.HasPrefix(withHTTP11, "t12d") {
		t.Errorf("TLS 1.2 client produced %q, want a t12d prefix", withHTTP11)
	}
}

// TestListenerEvictsOnClose guards the one way this design could leak: the
// table is process-wide, so entries have to go when connections do.
func TestListenerEvictsOnClose(t *testing.T) {
	server, clientConn := handshake(t, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		MinVersion:         tls.VersionTLS13,
	})

	key := normalizeAddr(clientConn.LocalAddr().String())
	if conns.get(key) == "" {
		t.Fatal("no fingerprint recorded for the connection")
	}

	server.close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conns.get(key) == "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("fingerprint still cached after the connection closed")
}

// TestListenerPassesThroughPlaintext makes sure wrapping a listener cannot
// break traffic that is not TLS at all — the bytes must arrive unchanged and
// no fingerprint should be invented.
func TestListenerPassesThroughPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	wrapper := &ListenerWrapper{MaxCaptureBytes: defaultMaxCaptureBytes}
	wrapped := wrapper.WrapListener(ln)

	const message = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	received := make(chan []byte, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		buf := make([]byte, len(message))
		if _, err := io.ReadFull(conn, buf); err != nil {
			received <- nil
			return
		}
		received <- buf
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, []byte(message)) {
			t.Errorf("server read %q, want %q", got, message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the plaintext request")
	}

	if fingerprint := conns.get(normalizeAddr(conn.LocalAddr().String())); fingerprint != "" {
		t.Errorf("plaintext connection produced fingerprint %q, want none", fingerprint)
	}
}

// testServer is a wrapped TLS listener kept alive for the duration of a test.
type testServer struct {
	ln     net.Listener
	closed chan struct{}
}

func (s *testServer) close() {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.ln.Close()
}

// handshake starts a TLS server behind the ja4 listener wrapper, completes one
// handshake from a client using clientConfig, and returns the server and the
// client side of the connection. The client connection stays open so that its
// cache entry is still there for the caller to inspect.
func handshake(t *testing.T, clientConfig *tls.Config) (*testServer, *tls.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	wrapper := &ListenerWrapper{MaxCaptureBytes: defaultMaxCaptureBytes}
	tlsListener := tls.NewListener(wrapper.WrapListener(ln), &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})

	server := &testServer{ln: tlsListener, closed: make(chan struct{})}
	accepted := make(chan error, 1)

	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		tlsConn := conn.(*tls.Conn)
		accepted <- tlsConn.Handshake()
		<-server.closed
		conn.Close()
	}()

	clientConn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		server.close()
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })

	select {
	case err := <-accepted:
		if err != nil {
			server.close()
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		server.close()
		t.Fatal("timed out waiting for the server handshake")
	}

	return server, clientConn
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
