package botpolicy

import (
	"bytes"
	"net"
	"sync"
	"time"
)

// fingerprintStore maps a live connection to the JA4 computed from its
// ClientHello.
//
// The listener wrapper and the HTTP handler are separate Caddy modules with
// no reference to each other, and by the time the handler runs the raw
// connection is buried under the TLS layer, so a process-wide table keyed by
// both TCP endpoints is what bridges them. Different local listeners can
// receive connections from the same remote IP:port simultaneously. Entries
// are dropped on Close.
type fingerprintStore struct {
	mu sync.RWMutex
	m  map[string]fingerprints
}

type fingerprints struct {
	ja4  string // spec-exact JA4 for the blocklist and logging
	bind string // resumption-insensitive JA4 variant for clearances
}

// conns is the table shared by the ja4 listener wrapper and the ja4 handler.
var conns = &fingerprintStore{m: make(map[string]fingerprints)}

func (s *fingerprintStore) set(addr, fingerprint string) {
	s.setPair(addr, fingerprint, "")
}

func (s *fingerprintStore) setPair(addr, fingerprint, bind string) {
	if addr == "" || fingerprint == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[addr] = fingerprints{ja4: fingerprint, bind: bind}
}

func (s *fingerprintStore) get(addr string) string {
	return s.getPair(addr).ja4
}

func (s *fingerprintStore) getBind(addr string) string {
	return s.getPair(addr).bind
}

func (s *fingerprintStore) getPair(addr string) fingerprints {
	if addr == "" {
		return fingerprints{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[addr]
}

func (s *fingerprintStore) delete(addr string) {
	if addr == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, addr)
}

func (s *fingerprintStore) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// normalizeAddr canonicalizes a "host:port" address so that the listener side
// and the handler side agree on the key. Both get their value from Go's net
// package and should already match, but IPv6 in particular has several
// spellings of the same address, so the host half is round-tripped through
// net.IP.
func normalizeAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(host, port)
}

// tcpConnectionKey disambiguates connections to different local listeners.
func tcpConnectionKey(remote, local string) string {
	if remote == "" || local == "" {
		return ""
	}
	return normalizeAddr(remote) + "|" + normalizeAddr(local)
}

// idleStore maps a QUIC client address to the JA4 of its ClientHello.
//
// Unlike TCP there is no per-connection Close to hook: the packet conn sees
// datagrams, not connections. Entries therefore expire after going unread
// for ttl (every HTTP/3 request on the connection refreshes its entry), are
// capped in number, and are dropped as soon as a new connection attempt from
// the same address is seen (see quicSniffer.add).
type idleStore struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu        sync.Mutex
	m         map[string]idleEntry
	lastSweep time.Time
}

type idleEntry struct {
	fingerprints
	seen time.Time
	dcid []byte // completed QUIC ClientHello's connection identity
}

func newIdleStore(ttl time.Duration, max int) *idleStore {
	return &idleStore{ttl: ttl, max: max, now: time.Now, m: make(map[string]idleEntry)}
}

// quicConns is the table shared by the ja4 packet conn wrapper and the ja4
// handler for requests that arrive over HTTP/3.
//
// The TTL is far longer than quic-go's default 30 s idle timeout, because a
// client can keep a connection open with PINGs while sending no requests,
// and the entry is only refreshed by requests. Stale entries cannot leak to
// a different connection: a new connection from the same address starts
// with an Initial, which clears the old entry.
var quicConns = newIdleStore(time.Hour, 100_000)

func (s *idleStore) set(addr, fingerprint string) {
	s.setPair(addr, fingerprint, "")
}

func (s *idleStore) setPair(addr, fingerprint, bind string) {
	s.setPairWithDCID(addr, fingerprint, bind, nil)
}

func (s *idleStore) setPairWithDCID(addr, fingerprint, bind string, dcid []byte) {
	if addr == "" || fingerprint == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Sweeping is O(n), so even when full it runs at most once a second;
	// otherwise a flood of spoofed hellos could make every insert a full scan.
	if since := now.Sub(s.lastSweep); since > s.ttl/4 || (len(s.m) >= s.max && since > time.Second) {
		s.sweepLocked(now)
	}
	if _, exists := s.m[addr]; !exists && len(s.m) >= s.max {
		return // full of live connections: fail open rather than evict them
	}
	s.m[addr] = idleEntry{fingerprints: fingerprints{ja4: fingerprint, bind: bind}, seen: now, dcid: bytes.Clone(dcid)}
}

// sameDCID reports whether this Initial belongs to an already captured
// connection. A new DCID must invalidate the previous address attribution.
func (s *idleStore) sameDCID(addr string, dcid []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[addr]
	return ok && s.now().Sub(e.seen) <= s.ttl && e.dcid != nil && bytes.Equal(e.dcid, dcid)
}

func (s *idleStore) get(addr string) string {
	return s.getPair(addr).ja4
}

func (s *idleStore) getBind(addr string) string {
	return s.getPair(addr).bind
}

func (s *idleStore) getPair(addr string) fingerprints {
	if addr == "" {
		return fingerprints{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[addr]
	if !ok {
		return fingerprints{}
	}
	now := s.now()
	if now.Sub(e.seen) > s.ttl {
		delete(s.m, addr)
		return fingerprints{}
	}
	e.seen = now
	s.m[addr] = e
	return e.fingerprints
}

func (s *idleStore) delete(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, addr)
}

func (s *idleStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func (s *idleStore) sweepLocked(now time.Time) {
	s.lastSweep = now
	for k, e := range s.m {
		if now.Sub(e.seen) > s.ttl {
			delete(s.m, k)
		}
	}
}
