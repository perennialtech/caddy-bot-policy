package botpolicy

import (
	"net"
	"strconv"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/ipv4"
)

// PacketConnWrapper captures the TLS ClientHello from QUIC Initial packets
// so that requests arriving over HTTP/3 get a JA4 fingerprint too. It is the
// QUIC counterpart of ListenerWrapper and is configured on the same server:
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
// It sits between the UDP socket and quic-go. Every datagram is checked for
// a long-header Initial packet; established connections only send short
// headers, so the per-packet cost after the handshake is one byte test.
type PacketConnWrapper struct {
	// MaxCaptureBytes bounds the size of a ClientHello that will be
	// reassembled from CRYPTO frames. Defaults to 16384.
	MaxCaptureBytes int `json:"max_capture_bytes,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (PacketConnWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.packetconns.ja4",
		New: func() caddy.Module { return new(PacketConnWrapper) },
	}
}

// Provision sets up pw.
func (pw *PacketConnWrapper) Provision(caddy.Context) error {
	if pw.MaxCaptureBytes <= 0 {
		pw.MaxCaptureBytes = defaultMaxCaptureBytes
	}
	if pw.MaxCaptureBytes < minCaptureBytes {
		pw.MaxCaptureBytes = minCaptureBytes
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	ja4 {
//		max_capture_bytes 16384
//	}
func (pw *PacketConnWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "max_capture_bytes":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid max_capture_bytes %q: %v", d.Val(), err)
				}
				pw.MaxCaptureBytes = n
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized ja4 packet conn option '%s'", d.Val())
			}
		}
	}
	return nil
}

// WrapPacketConn implements caddy.PacketConnWrapper.
func (pw *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	max := pw.MaxCaptureBytes
	if max <= 0 {
		max = defaultMaxCaptureBytes
	}
	return wrapPacketConn(pc, newQUICSniffer(max, quicConns))
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

// wrapPacketConn returns pc with its reads observed by s.
//
// The optimised path is safe only when pc itself exposes UDP/OOB methods.
// Even Caddy's own Unwrap-capable listener can implement essential read
// semantics (notably clearing a shutdown deadline during a reload).
// Bypassing an outer wrapper to reach a UDP socket would skip those hooks.
func wrapPacketConn(pc net.PacketConn, s *quicSniffer) net.PacketConn {
	base := &sniffPacketConn{PacketConn: pc, sniffer: s}

	if oob, ok := pc.(oobCapablePacketConn); ok {
		return &sniffOOBPacketConn{
			sniffPacketConn: base,
			raw:             oob,
			batch:           ipv4.NewPacketConn(oob),
		}
	}
	return base
}

// sniffPacketConn observes every datagram read through ReadFrom.
type sniffPacketConn struct {
	net.PacketConn
	sniffer *quicSniffer
}

func (c *sniffPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 && addr != nil {
		c.sniffer.observe(addr.String(), p[:n])
	}
	return n, addr, err
}

// sniffOOBPacketConn additionally provides quic-go's optimised read path,
// reading through the supplied OOB-capable packet conn.
type sniffOOBPacketConn struct {
	*sniffPacketConn
	raw   oobCapablePacketConn
	batch *ipv4.PacketConn
}

func (c *sniffOOBPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.raw.ReadFrom(p)
	if n > 0 && addr != nil {
		c.sniffer.observe(addr.String(), p[:n])
	}
	return n, addr, err
}

func (c *sniffOOBPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.raw.WriteTo(p, addr)
}

func (c *sniffOOBPacketConn) SyscallConn() (syscall.RawConn, error) { return c.raw.SyscallConn() }
func (c *sniffOOBPacketConn) SetReadBuffer(n int) error             { return c.raw.SetReadBuffer(n) }
func (c *sniffOOBPacketConn) SetWriteBuffer(n int) error            { return c.raw.SetWriteBuffer(n) }

func (c *sniffOOBPacketConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, addr, err := c.raw.ReadMsgUDP(b, oob)
	if n > 0 && addr != nil {
		c.sniffer.observe(addr.String(), b[:n])
	}
	return n, oobn, flags, addr, err
}

func (c *sniffOOBPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return c.raw.WriteMsgUDP(b, oob, addr)
}

// ReadBatch lets quic-go read many datagrams per syscall, as it would from
// the bare socket.
func (c *sniffOOBPacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n, err := c.batch.ReadBatch(ms, flags)
	for i := range n {
		m := &ms[i]
		if m.N > 0 && m.Addr != nil && len(m.Buffers) > 0 {
			c.sniffer.observe(m.Addr.String(), m.Buffers[0][:m.N])
		}
	}
	return n, err
}

// Interface guards.
var (
	_ caddy.Provisioner       = (*PacketConnWrapper)(nil)
	_ caddy.PacketConnWrapper = (*PacketConnWrapper)(nil)
	_ caddyfile.Unmarshaler   = (*PacketConnWrapper)(nil)
	_ oobCapablePacketConn    = (*sniffOOBPacketConn)(nil)
)
