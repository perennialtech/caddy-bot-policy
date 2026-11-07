package botpolicy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// hiddenOOB wraps a UDP socket so that only the net.PacketConn methods are
// visible, the way an unknown third-party wrapper earlier in the chain would.
type hiddenOOB struct{ net.PacketConn }

// quicFingerprintServer runs a QUIC server wired the way Caddy wires a
// caddy.QUICHandshakeObserver: ConnContext on the transport, and the
// ClientHello observed before the TLS config is chosen. Each stream is
// answered with the fingerprint of its connection and the client address
// the server currently sees.
func quicFingerprintServer(t *testing.T, pc net.PacketConn) {
	t.Helper()
	pw := &PacketConnWrapper{}
	tr := &quic.Transport{Conn: pw.WrapPacketConn(pc), ConnContext: pw.QUICConnContext}
	t.Cleanup(func() { tr.Close() })
	cert := selfSignedCert(t)
	ln, err := tr.Listen(&tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			pw.ObserveQUICClientHello(hello)
			return nil, nil
		},
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "h3-alt"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					io.ReadAll(str)
					fp := quicConnFingerprint(conn.Context())
					io.WriteString(str, fp.ja4+" "+fp.bind+" "+conn.RemoteAddr().String())
					str.Close()
				}
			}()
		}
	}()
}

// ask opens a stream on conn and returns the server's answer: the exact and
// bind fingerprints and the client address the server sees.
func ask(t *testing.T, ctx context.Context, conn *quic.Conn) (exact, bind, remote string) {
	t.Helper()
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	str.Write([]byte("?"))
	str.Close()
	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(got))
	if len(f) != 3 {
		t.Fatalf("server answered %q", got)
	}
	return f[0], f[1], f[2]
}

func clientTLS(alpn string) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: "example.com", NextProtos: []string{alpn}}
}

// TestPacketConnWrapperRealQUICHandshake runs genuine quic-go handshakes
// through the wrapper, on both read paths quic-go can take: batched reads on
// the bare socket (Linux), and plain ReadFrom when the socket is hidden.
func TestPacketConnWrapperRealQUICHandshake(t *testing.T) {
	for _, tc := range []struct {
		name    string
		hide    bool
		wantOOB bool
	}{
		{"socket exposed", false, true},
		{"socket hidden", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			var pc net.PacketConn = udp
			if tc.hide {
				pc = hiddenOOB{udp}
			}
			if _, isOOB := wrapPacketConn(pc).(*oobPacketConn); isOOB != tc.wantOOB {
				t.Fatalf("wrapper exposes quic-go's optimised path: %v, want %v", isOOB, tc.wantOOB)
			}
			quicFingerprintServer(t, pc)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := quic.DialAddr(ctx, udp.LocalAddr().String(), clientTLS("h3"), nil)
			if err != nil {
				t.Fatalf("handshake through the wrapper failed: %v", err)
			}
			defer client.CloseWithError(0, "")

			exact, bind, _ := ask(t, ctx, client)
			// q = QUIC, 13 = TLS 1.3, d = SNI sent, h3 = first ALPN.
			if len(exact) != 36 || exact[:4] != "q13d" || exact[8:10] != "h3" {
				t.Fatalf("fingerprint %q, want q13d....h3_<12>_<12>", exact)
			}
			if len(bind) != 36 || bind[:10] != exact[:10] {
				t.Fatalf("bind fingerprint %q does not match exact %q", bind, exact)
			}
		})
	}
}

// Connections from one UDP address each keep the fingerprint of their own
// ClientHello: a later Initial from that address, here a full connection
// with a different client profile, cannot change an established one's.
func TestQUICFingerprintIsolatesConnectionsFromSameAddress(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	quicFingerprintServer(t, udp)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client := &quic.Transport{Conn: clientUDP}
	defer client.Close()

	first, err := client.Dial(ctx, udp.LocalAddr(), clientTLS("h3"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseWithError(0, "")
	before, _, remote1 := ask(t, ctx, first)

	second, err := client.Dial(ctx, udp.LocalAddr(), clientTLS("h3-alt"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.CloseWithError(0, "")
	other, _, remote2 := ask(t, ctx, second)

	if remote1 != remote2 {
		t.Fatalf("connections came from %s and %s, want one address", remote1, remote2)
	}
	if other == before {
		t.Fatalf("different client profiles produced the same fingerprint %q", other)
	}
	if after, _, _ := ask(t, ctx, first); after != before {
		t.Fatalf("first connection's fingerprint changed from %q to %q after another Initial from its address", before, after)
	}
}

// A connection that migrates to a new client address keeps its fingerprint.
func TestQUICFingerprintSurvivesMigration(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	quicFingerprintServer(t, udp)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newTransport := func() *quic.Transport {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		tr := &quic.Transport{Conn: c}
		t.Cleanup(func() { tr.Close() })
		return tr
	}

	conn, err := newTransport().Dial(ctx, udp.LocalAddr(), clientTLS("h3"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	before, bindBefore, remoteBefore := ask(t, ctx, conn)

	path, err := conn.AddPath(newTransport())
	if err != nil {
		t.Fatal(err)
	}
	if err := path.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := path.Switch(); err != nil {
		t.Fatal(err)
	}

	// The server switches only once it has validated the new path, which
	// can take a round trip after the client switched.
	after, bindAfter, remoteAfter := ask(t, ctx, conn)
	for remoteAfter == remoteBefore && ctx.Err() == nil {
		time.Sleep(10 * time.Millisecond)
		after, bindAfter, remoteAfter = ask(t, ctx, conn)
	}
	if remoteAfter == remoteBefore {
		t.Fatalf("server still sees %s; the connection did not migrate", remoteAfter)
	}
	if after != before || bindAfter != bindBefore {
		t.Fatalf("fingerprint changed on migration: %q/%q, want %q/%q", after, bindAfter, before, bindBefore)
	}
}

func TestPacketConnWrapperClosesThroughOuterConn(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	outer := &closeRecorder{PacketConn: udp}
	wrapped := wrapPacketConn(outer)
	if _, ok := wrapped.(*oobPacketConn); !ok {
		t.Fatal("expected the optimised path once the socket is unwrapped")
	}
	wrapped.Close()
	if !outer.closed {
		t.Fatal("Close bypassed the outer conn; Caddy's listener reuse depends on it")
	}
}

// closeRecorder stands in for Caddy's own packet conn bookkeeping types,
// which expose the socket through Unwrap and must see Close.
type closeRecorder struct {
	net.PacketConn
	closed bool
}

func (c *closeRecorder) Close() error           { c.closed = true; return nil }
func (c *closeRecorder) Unwrap() net.PacketConn { return c.PacketConn }
