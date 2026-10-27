package botpolicy

import (
	"bufio"
	"net"
	"strconv"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

// defaultMaxCaptureBytes bounds how much of the connection is buffered while
// waiting for a complete ClientHello. One TLS record tops out at 16 KiB, and
// post-quantum key shares have pushed real hellos past 2 KiB, so this leaves
// room without letting a client make the server buffer arbitrarily.
const defaultMaxCaptureBytes = 16384

// minCaptureBytes is the smallest useful buffer: below this even a modest
// hello would be truncated and no connection would ever be fingerprinted.
const minCaptureBytes = 1024

// ListenerWrapper captures the TLS ClientHello at the start of each
// connection and records its JA4 fingerprint for the ja4 HTTP handler to
// publish.
//
// It has to run before TLS is terminated — once the handshake completes the
// hello is gone, and Go's tls.ConnectionState exposes only the negotiated
// result, not the offered cipher and extension lists JA4 is built from. In
// Caddyfile terms that means listing it ahead of the tls placeholder:
//
//	{
//		servers {
//			listener_wrappers {
//				ja4
//				tls
//			}
//		}
//	}
//
// Only TCP listeners pass through here. HTTP/3 runs over UDP and is covered
// by the ja4 packet conn wrapper (PacketConnWrapper) instead.
type ListenerWrapper struct {
	// MaxCaptureBytes is how many bytes may be buffered while waiting for the
	// ClientHello. Defaults to 16384.
	MaxCaptureBytes int `json:"max_capture_bytes,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets up lw.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger()
	if lw.MaxCaptureBytes <= 0 {
		lw.MaxCaptureBytes = defaultMaxCaptureBytes
	}
	if lw.MaxCaptureBytes < minCaptureBytes {
		lw.MaxCaptureBytes = minCaptureBytes
	}
	return nil
}

// WrapListener implements caddy.ListenerWrapper.
func (lw *ListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &ja4Listener{Listener: ln, max: lw.MaxCaptureBytes, logger: lw.logger}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	ja4 {
//		max_capture_bytes 16384
//	}
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
				lw.MaxCaptureBytes = n
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized ja4 listener option '%s'", d.Val())
			}
		}
	}
	return nil
}

type ja4Listener struct {
	net.Listener
	max    int
	logger *zap.Logger
}

func (l *ja4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedConn{
		Conn:   conn,
		reader: bufio.NewReaderSize(conn, l.max),
		addr:   normalizeAddr(conn.RemoteAddr().String()),
		max:    l.max,
		logger: l.logger,
	}, nil
}

// trackedConn peeks at the head of the connection to compute a fingerprint,
// then behaves like the connection it wraps.
type trackedConn struct {
	net.Conn

	reader *bufio.Reader
	addr   string
	max    int
	logger *zap.Logger

	sniffOnce sync.Once
	closeOnce sync.Once
}

// Read computes the fingerprint on the first call, before handing any bytes
// to the TLS stack. Peeking never consumes, so the handshake still sees the
// stream from byte zero.
func (c *trackedConn) Read(p []byte) (int, error) {
	c.sniffOnce.Do(c.sniff)
	return c.reader.Read(p)
}

// Close drops the cache entry. Without this the table would grow for the
// lifetime of the process.
func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() { conns.delete(c.addr) })
	return c.Conn.Close()
}

// sniff reads far enough into the connection to assemble the ClientHello,
// computes the JA4 and stores it.
//
// Every failure path is silent by design: anything that is not a readable
// ClientHello (plain HTTP on the same port, a truncated hello, a client that
// hangs up) leaves the connection untouched and simply produces no
// fingerprint, which bot_policy then resolves through
// on_missing_fingerprint.
func (c *trackedConn) sniff() {
	need := recordHeaderLen
	for {
		if need > c.max {
			c.debug("client hello exceeds max_capture_bytes", zap.Int("need", need), zap.Int("max", c.max))
			return
		}

		buf, err := c.reader.Peek(need)
		if err != nil {
			// Short read: use whatever arrived. A well-formed hello will fail
			// the length checks below and be dropped.
			if len(buf) == 0 {
				return
			}
		}

		body, more, err := handshakeBody(buf)
		if err != nil {
			if more == 0 || more <= need {
				// Not a client hello, or no way to make progress.
				return
			}
			need = more
			continue
		}

		hello, err := parseClientHello(body)
		if err != nil {
			c.debug("could not parse client hello", zap.Error(err))
			return
		}

		fingerprint := hello.ja4(transportTCP)
		conns.set(c.addr, fingerprint)
		c.debug("computed ja4", zap.String("remote_addr", c.addr), zap.String("ja4", fingerprint))
		return
	}
}

func (c *trackedConn) debug(msg string, fields ...zap.Field) {
	if c.logger == nil {
		return
	}
	c.logger.Debug(msg, fields...)
}

// Interface guards.
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)
