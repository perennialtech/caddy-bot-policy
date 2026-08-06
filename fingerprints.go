package botpolicy

import (
	"net"
	"sync"
)

// fingerprintStore maps a live connection to the JA4 computed from its
// ClientHello.
//
// The listener wrapper and the HTTP handler are separate Caddy modules with
// no reference to each other, and by the time the handler runs the raw
// connection is buried under the TLS layer, so a process-wide table keyed by
// remote address is what bridges them. The key is unique while it matters: a
// TCP four-tuple cannot be reused while the connection is open, and entries
// are dropped on Close.
type fingerprintStore struct {
	mu sync.RWMutex
	m  map[string]string
}

// conns is the table shared by the ja4 listener wrapper and the ja4 handler.
var conns = &fingerprintStore{m: make(map[string]string)}

func (s *fingerprintStore) set(addr, fingerprint string) {
	if addr == "" || fingerprint == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[addr] = fingerprint
}

func (s *fingerprintStore) get(addr string) string {
	if addr == "" {
		return ""
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
