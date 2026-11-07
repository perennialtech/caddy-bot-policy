package botpolicy

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/ipv4"
)

// PacketConnWrapper fingerprints the TLS ClientHello of each QUIC (HTTP/3)
// connection. It is the QUIC counterpart of ListenerWrapper and is
// configured on the same server:
//
//	{
//		servers {
//			listener_wrappers {
//				ja4
//				tls
//			}
//			packet_conn_wrappers {
//				ja4
//			}
//		}
//	}
//
// The fingerprint is taken from the ClientHello that quic-go's TLS stack
// actually processed for the connection and is kept in that connection's
// context, which every HTTP/3 request on it inherits. Unauthenticated
// Initial packets from the same UDP address therefore cannot change it, and
// connection migration does not lose it.
//
// This needs the caddy.QUICHandshakeObserver hook from the
// perennialtech/caddy fork; see the README.
type PacketConnWrapper struct{}

// CaddyModule returns the Caddy module information.
func (PacketConnWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.packetconns.ja4",
		New: func() caddy.Module { return new(PacketConnWrapper) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (pw *PacketConnWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		if d.NextBlock(0) {
			return d.Errf("unrecognized ja4 packet conn option '%s'", d.Val())
		}
	}
	return nil
}

// quicFingerprintKey is the connection context key for a *quicFingerprint.
type quicFingerprintKey struct{}

// quicFingerprint is filled in from the connection's ClientHello during the
// handshake and read by the requests the connection carries.
type quicFingerprint struct {
	atomic.Pointer[fingerprints]
}

// QUICConnContext implements caddy.QUICHandshakeObserver.
func (*PacketConnWrapper) QUICConnContext(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
	return context.WithValue(ctx, quicFingerprintKey{}, new(quicFingerprint)), nil
}

// ObserveQUICClientHello implements caddy.QUICHandshakeObserver.
func (*PacketConnWrapper) ObserveQUICClientHello(hello *tls.ClientHelloInfo) {
	slot, ok := hello.Context().Value(quicFingerprintKey{}).(*quicFingerprint)
	if !ok {
		return
	}
	ch := clientHelloFromInfo(hello)
	slot.Store(&fingerprints{ja4: ch.ja4(transportQUIC), bind: ch.ja4Bind(transportQUIC)})
}

// quicConnFingerprint returns the fingerprint of the QUIC connection that
// carried the request with context ctx. It is empty when the packet conn
// wrapper is not configured or the handshake never reached the ClientHello.
func quicConnFingerprint(ctx context.Context) fingerprints {
	slot, ok := ctx.Value(quicFingerprintKey{}).(*quicFingerprint)
	if !ok {
		return fingerprints{}
	}
	if fp := slot.Load(); fp != nil {
		return *fp
	}
	return fingerprints{}
}

// WrapPacketConn implements caddy.PacketConnWrapper.
func (pw *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	return wrapPacketConn(pc)
}

// oobCapablePacketConn is the method set quic-go looks for (its
// OOBCapablePacketConn) to enable batched reads, GSO and ECN on Linux.
// *net.UDPConn has it.
type oobCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

// wrapPacketConn returns pc with the underlying socket's optimised method
// set exposed.
//
// The wrapper only exists so that Caddy hands this module to its QUIC
// listener. When no wrapper is configured, Caddy hands quic-go the bare UDP
// socket (it unwraps its own bookkeeping types first) so quic-go can batch
// reads with recvmmsg, use GSO and read destination addresses. Returning pc
// as is would hide the socket and silently cost those, so when the socket is
// reachable the wrapper re-exposes the same method set. Close still goes to
// pc, so Caddy's listener reuse across config reloads behaves exactly as it
// does without the wrapper.
func wrapPacketConn(pc net.PacketConn) net.PacketConn {
	raw := pc
	for {
		u, ok := raw.(interface{ Unwrap() net.PacketConn })
		if !ok {
			break
		}
		raw = u.Unwrap()
	}
	if oob, ok := raw.(oobCapablePacketConn); ok {
		return &oobPacketConn{
			PacketConn: pc,
			raw:        oob,
			batch:      ipv4.NewPacketConn(oob),
		}
	}
	return pc
}

// oobPacketConn provides quic-go's optimised read path, reading from the
// underlying socket directly.
type oobPacketConn struct {
	net.PacketConn
	raw   oobCapablePacketConn
	batch *ipv4.PacketConn
}

func (c *oobPacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return c.raw.ReadFrom(p) }

func (c *oobPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.raw.WriteTo(p, addr)
}

func (c *oobPacketConn) SyscallConn() (syscall.RawConn, error) { return c.raw.SyscallConn() }
func (c *oobPacketConn) SetReadBuffer(n int) error             { return c.raw.SetReadBuffer(n) }
func (c *oobPacketConn) SetWriteBuffer(n int) error            { return c.raw.SetWriteBuffer(n) }

func (c *oobPacketConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return c.raw.ReadMsgUDP(b, oob)
}

func (c *oobPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return c.raw.WriteMsgUDP(b, oob, addr)
}

// ReadBatch lets quic-go read many datagrams per syscall, as it would from
// the bare socket.
func (c *oobPacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.batch.ReadBatch(ms, flags)
}

// Interface guards.
var (
	_ caddy.PacketConnWrapper     = (*PacketConnWrapper)(nil)
	_ caddy.QUICHandshakeObserver = (*PacketConnWrapper)(nil)
	_ caddyfile.Unmarshaler       = (*PacketConnWrapper)(nil)
	_ oobCapablePacketConn        = (*oobPacketConn)(nil)
)
