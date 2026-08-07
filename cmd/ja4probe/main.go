// Command ja4probe is a throwaway HTTPS server that prints the JA4 of every
// client that connects to it, next to the User-Agent that client sent.
//
// It exists to build and audit a catalogue of known fingerprints. A JA4
// catalogue is a list of opaque hashes, so the only way to keep one honest is
// to be able to regenerate every entry on demand: point a real client at this
// probe and read off the pair.
//
//	go run ./cmd/ja4probe -addr :8443
//	curl -sk https://localhost:8443/
//
//	t13d3112h2_e8f1e7e78f70_6bebaf5ad700  curl/8.5.0
//
// The certificate is self-signed and generated on every start, so clients need
// to be told to skip verification (curl -k, requests' verify=False, a browser
// click-through). That is fine: the fingerprint is taken from the ClientHello,
// which the client sends before it ever sees a certificate.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	botpolicy "github.com/carbans/caddy-bot-policy"
)

// maxCaptureBytes bounds how much of the connection is buffered while waiting
// for a complete ClientHello. A TLS record tops out at 16 KiB and hellos
// carrying post-quantum key shares already exceed 2 KiB.
const maxCaptureBytes = 16384

func main() {
	addr := flag.String("addr", ":8443", "address to listen on")
	flag.Parse()

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("generating certificate: %v", err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Fprintf(os.Stderr, "ja4probe listening on %s\n\n", ln.Addr())

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The fingerprint was printed when the connection was accepted;
			// printing the User-Agent here pairs the two, which is the whole
			// point of the tool.
			fmt.Printf("  user-agent  %s\n          alpn  %s\n\n",
				r.UserAgent(), r.Proto)
			fmt.Fprintln(w, "ok")
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}

	// ServeTLS, not Serve: the latter ignores TLSConfig and would hand the
	// raw connection to the HTTP parser, which reads the ClientHello as a
	// malformed request line.
	log.Fatal(server.ServeTLS(&probeListener{Listener: ln}, "", ""))
}

// probeListener fingerprints each accepted connection before handing it to the
// TLS server.
type probeListener struct{ net.Listener }

func (l *probeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	captured, fingerprint, err := fingerprintConn(conn)
	if err != nil {
		fmt.Printf("%-24s  %v\n", conn.RemoteAddr(), err)
	} else {
		fmt.Printf("ja4           %s\n", fingerprint)
	}

	// Whatever was read to find the ClientHello has to be replayed, or the TLS
	// server sees a handshake that starts mid-message.
	return &replayConn{Conn: conn, pending: captured}, nil
}

// fingerprintConn reads from conn until it holds a complete ClientHello,
// returning the bytes consumed alongside the fingerprint.
func fingerprintConn(conn net.Conn) ([]byte, string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, "", err
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck // best effort

	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 2048)
	for {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)

		if fingerprint, ferr := botpolicy.Fingerprint(buf); ferr == nil {
			return buf, fingerprint, nil
		}
		if err != nil {
			return buf, "", fmt.Errorf("read: %w", err)
		}
		if len(buf) >= maxCaptureBytes {
			return buf, "", errors.New("no ClientHello within capture limit")
		}
	}
}

// replayConn serves the already-consumed bytes before reading from the wire.
type replayConn struct {
	net.Conn
	pending []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ja4probe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
