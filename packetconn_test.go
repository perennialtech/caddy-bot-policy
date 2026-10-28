package botpolicy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
)

// loopbackKey is the address the server sees for a quic-go client dialing
// 127.0.0.1: the client socket is bound to the wildcard address, so its own
// LocalAddr reports 0.0.0.0 or [::] rather than the loopback source.
func loopbackKey(t *testing.T, local net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(local.String())
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// hiddenOOB wraps a UDP socket so that only the net.PacketConn methods are
// visible, the way an unknown third-party wrapper earlier in the chain would.
type hiddenOOB struct{ net.PacketConn }

// TestPacketConnWrapperRealQUICHandshake runs genuine quic-go handshakes
// through the wrapper, on both read paths quic-go can take: batched reads on
// the bare socket (Linux), and plain ReadFrom when the socket is hidden.
// It checks the connection still works and that a fingerprint comes out.
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

			store := newIdleStore(time.Hour, 100)
			wrapped := wrapPacketConn(pc, newQUICSniffer(defaultMaxCaptureBytes, store))
			if _, isOOB := wrapped.(*sniffOOBPacketConn); isOOB != tc.wantOOB {
				t.Fatalf("wrapper exposes quic-go's optimised path: %v, want %v", isOOB, tc.wantOOB)
			}

			tr := &quic.Transport{Conn: wrapped}
			defer tr.Close()
			ln, err := tr.Listen(&tls.Config{
				Certificates: []tls.Certificate{selfSignedCert(t)},
				NextProtos:   []string{"h3"},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Echo server: proves the data path still works through the wrapper.
			go func() {
				conn, err := ln.Accept(ctx)
				if err != nil {
					return
				}
				str, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				io.Copy(str, str)
				str.Close()
			}()

			client, err := quic.DialAddr(ctx, udp.LocalAddr().String(), &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "example.com",
				NextProtos:         []string{"h3"},
			}, nil)
			if err != nil {
				t.Fatalf("handshake through the wrapper failed: %v", err)
			}
			defer client.CloseWithError(0, "")

			str, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("ping through the wrapper")
			if _, err := str.Write(msg); err != nil {
				t.Fatal(err)
			}
			str.Close()
			got, err := io.ReadAll(str)
			if err != nil || string(got) != string(msg) {
				t.Fatalf("echo got %q, %v", got, err)
			}

			fp := store.get(loopbackKey(t, client.LocalAddr()))
			// q = QUIC, 13 = TLS 1.3, d = SNI sent, h3 = first ALPN.
			if len(fp) != 36 || fp[:4] != "q13d" || fp[8:10] != "h3" {
				t.Fatalf("fingerprint %q, want q13d....h3_<12>_<12>", fp)
			}

			// A second connection from quic-go's client must land on the same
			// value: QUIC fingerprints are only useful if they are stable.
			client2, err := quic.DialAddr(ctx, udp.LocalAddr().String(), &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "example.com",
				NextProtos:         []string{"h3"},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client2.CloseWithError(0, "")
			if fp2 := store.get(loopbackKey(t, client2.LocalAddr())); fp2 != fp {
				t.Errorf("second connection fingerprint %q, want %q", fp2, fp)
			}
		})
	}
}

func TestPacketConnWrapperClosesThroughOuterConn(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	outer := &closeRecorder{PacketConn: udp}
	wrapped := wrapPacketConn(outer, newQUICSniffer(defaultMaxCaptureBytes, newIdleStore(time.Hour, 10)))
	if _, ok := wrapped.(*sniffOOBPacketConn); ok {
		t.Fatal("unwrapping skipped the outer connection's I/O methods")
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

// deadlineRecoveryConn models Caddy's fakeClosePacketConn. A close interrupts
// an old reader but the socket itself must remain usable by a new listener.
type deadlineRecoveryConn struct {
	net.PacketConn
	closed  atomic.Bool
	started chan struct{}
}

func (c *deadlineRecoveryConn) Unwrap() net.PacketConn { return c.PacketConn }
func (c *deadlineRecoveryConn) Close() error {
	c.closed.Store(true)
	return c.SetReadDeadline(time.Now())
}
func (c *deadlineRecoveryConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	close(c.started)
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil && c.closed.Load() {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			if resetErr := c.SetReadDeadline(time.Time{}); resetErr != nil {
				return n, addr, resetErr
			}
		}
	}
	return n, addr, err
}

func TestPacketConnWrapperRetainsReloadDeadlineRecovery(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	old := &deadlineRecoveryConn{PacketConn: udp, started: make(chan struct{})}
	wrapped := wrapPacketConn(old, newQUICSniffer(defaultMaxCaptureBytes, newIdleStore(time.Hour, 10)))
	if _, ok := wrapped.(*sniffOOBPacketConn); ok {
		t.Fatal("optimized reads would bypass the reload deadline recovery")
	}
	readDone := make(chan error, 1)
	go func() {
		_, _, err := wrapped.ReadFrom(make([]byte, 1500))
		readDone <- err
	}()
	<-old.started
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("old read was not interrupted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old read did not stop after close")
	}

	// New listener shares the same UDP socket, as Caddy does on a reload.
	next := wrapPacketConn(&closeRecorder{PacketConn: udp}, newQUICSniffer(defaultMaxCaptureBytes, newIdleStore(time.Hour, 10)))
	if err := udp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sender, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("after reload")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, _, err := next.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "after reload" {
		t.Fatalf("shared socket unusable after reload: n=%d err=%v", n, err)
	}
}

type observingPacketConn struct {
	net.PacketConn
	reads, writes int
}

func (c *observingPacketConn) Unwrap() net.PacketConn { return c.PacketConn }
func (c *observingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.reads++
	return c.PacketConn.ReadFrom(p)
}
func (c *observingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes++
	return c.PacketConn.WriteTo(p, addr)
}

func TestPacketConnWrapperPreservesOuterIO(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	outer := &observingPacketConn{PacketConn: udp}
	wrapped := wrapPacketConn(outer, newQUICSniffer(defaultMaxCaptureBytes, newIdleStore(time.Hour, 10)))
	if _, err := peer.WriteTo([]byte("inbound"), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := udp.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrapped.ReadFrom(make([]byte, 128)); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.WriteTo([]byte("outbound"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if outer.reads != 1 || outer.writes != 1 {
		t.Fatalf("outer I/O was bypassed: reads=%d writes=%d", outer.reads, outer.writes)
	}
}

func TestHandlerUsesQUICFingerprintForHTTP3(t *testing.T) {
	const addr = "198.51.100.7:4433"
	quicConns.set(addr, "q13d0312h3_55b375c5d22e_cd85d2d88918")
	tcpKey := tcpConnectionKey(addr, "127.0.0.1:443")
	conns.set(tcpKey, "t13d1516h2_8daaf6152771_e5627efa2ab1")
	defer quicConns.delete(addr)
	defer conns.delete(tcpKey)

	for proto, want := range map[int]string{
		3: "q13d0312h3_55b375c5d22e_cd85d2d88918",
		2: "t13d1516h2_8daaf6152771_e5627efa2ab1",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		req.ProtoMajor = proto
		vars := map[string]any{}
		ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars)
		if proto != 3 {
			ctx = context.WithValue(ctx, http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443})
		}
		req = req.WithContext(ctx)

		h := &Handler{VarName: "ja4"}
		if err := h.ServeHTTP(httptest.NewRecorder(), req, passThrough); err != nil {
			t.Fatal(err)
		}
		if got := vars["ja4"]; got != want {
			t.Errorf("HTTP/%d: fingerprint %v, want %q", proto, got, want)
		}
	}
}
