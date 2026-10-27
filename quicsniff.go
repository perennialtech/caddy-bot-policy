package botpolicy

import (
	"bytes"
	"slices"
	"sync"
	"time"
)

// Limits for the QUIC sniffer. UDP source addresses are trivially spoofed,
// so every piece of state an unauthenticated datagram can create is bounded
// in size, count and lifetime.
const (
	// quicMaxPendingHellos caps how many partially received ClientHellos are
	// held at once. A modern hello spans two or three Initial packets, so
	// entries normally live for one round trip.
	quicMaxPendingHellos = 4096
	// quicPendingTTL is how long a partial ClientHello may wait for the rest
	// of its CRYPTO data before it is discarded.
	quicPendingTTL = 10 * time.Second
	// quicMaxChunksPerHello bounds the CRYPTO fragments kept per hello; some
	// clients deliberately scatter the hello across many small frames.
	quicMaxChunksPerHello = 64
)

// pendingHello is a ClientHello whose CRYPTO data is still arriving.
type pendingHello struct {
	dcid    []byte
	chunks  []cryptoChunk
	size    int
	started time.Time
}

// quicSniffer turns client Initial datagrams into JA4 fingerprints, keyed by
// the client's address, which is what an HTTP/3 request's RemoteAddr holds.
type quicSniffer struct {
	maxHelloBytes int
	store         *idleStore
	now           func() time.Time

	mu        sync.Mutex
	pending   map[string]*pendingHello
	lastSweep time.Time
}

func newQUICSniffer(maxHelloBytes int, store *idleStore) *quicSniffer {
	return &quicSniffer{
		maxHelloBytes: maxHelloBytes,
		store:         store,
		now:           time.Now,
		pending:       make(map[string]*pendingHello),
	}
}

// observe inspects one received datagram. It is called on the read path of
// every packet, so it returns immediately unless the datagram can hold a
// client Initial — which established connections never send.
func (s *quicSniffer) observe(addr string, datagram []byte) {
	if !looksLikeQUICInitialDatagram(datagram) {
		return
	}
	initials, err := parseQUICInitialDatagram(datagram)
	if err != nil {
		return
	}
	key := normalizeAddr(addr)
	for _, in := range initials {
		s.add(key, in)
	}
}

func (s *quicSniffer) add(key string, in quicInitial) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	p := s.pending[key]
	if p != nil && (!bytes.Equal(p.dcid, in.dcid) || now.Sub(p.started) > quicPendingTTL) {
		// A new Destination Connection ID means a new connection attempt
		// (or the same one after a Retry); either way the old data is moot.
		delete(s.pending, key)
		p = nil
	}
	if p == nil {
		if len(in.chunks) == 0 {
			return // ACK-only Initial: nothing to assemble
		}
		// A different connection from this address must never inherit the
		// previous one's fingerprint, even if its own hello turns out to be
		// unreadable.
		s.store.delete(key)
		if len(s.pending) >= quicMaxPendingHellos {
			s.sweepPendingLocked(now)
			if len(s.pending) >= quicMaxPendingHellos {
				return
			}
		}
		p = &pendingHello{dcid: in.dcid, started: now}
		s.pending[key] = p
	}

	for _, ch := range in.chunks {
		if len(p.chunks) >= quicMaxChunksPerHello || p.size+len(ch.data) > s.maxHelloBytes ||
			ch.offset > uint64(s.maxHelloBytes) {
			delete(s.pending, key) // too big to be a hello we are willing to hold
			return
		}
		// The chunk aliases the decrypted payload, which is ours to keep.
		p.chunks = append(p.chunks, ch)
		p.size += len(ch.data)
	}

	body, done := assembleHello(p.chunks)
	if !done {
		return
	}
	delete(s.pending, key)
	hello, err := parseClientHello(body)
	if err != nil {
		return
	}
	s.store.setPair(key, hello.ja4(transportQUIC), hello.ja4Bind(transportQUIC))
}

func (s *quicSniffer) sweepPendingLocked(now time.Time) {
	if now.Sub(s.lastSweep) < time.Second {
		return // bounded work under a flood: at most one scan a second
	}
	s.lastSweep = now
	for k, p := range s.pending {
		if now.Sub(p.started) > quicPendingTTL {
			delete(s.pending, k)
		}
	}
}

// assembleHello stitches CRYPTO chunks back into the handshake stream and,
// once the stream holds a complete ClientHello message, returns its body.
// Chunks may arrive in any order, overlap, or repeat (retransmissions).
func assembleHello(chunks []cryptoChunk) (body []byte, done bool) {
	sorted := slices.Clone(chunks)
	slices.SortFunc(sorted, func(a, b cryptoChunk) int {
		switch {
		case a.offset < b.offset:
			return -1
		case a.offset > b.offset:
			return 1
		}
		return 0
	})

	var stream []byte
	for _, ch := range sorted {
		end := ch.offset + uint64(len(ch.data))
		if ch.offset > uint64(len(stream)) {
			break // gap: wait for the missing piece
		}
		if end > uint64(len(stream)) {
			stream = append(stream, ch.data[uint64(len(stream))-ch.offset:]...)
		}
	}

	if len(stream) < handshakeHeaderLen {
		return nil, false
	}
	if stream[0] != handshakeTypeClientHello {
		return nil, false
	}
	n := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if len(stream) < handshakeHeaderLen+n {
		return nil, false
	}
	return stream[handshakeHeaderLen : handshakeHeaderLen+n], true
}
