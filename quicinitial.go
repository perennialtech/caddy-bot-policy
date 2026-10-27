package botpolicy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// This file reads the TLS ClientHello out of QUIC Initial packets.
//
// Over QUIC there is no TLS record layer: the handshake travels in CRYPTO
// frames inside Initial packets. Initial packets are encrypted, but only for
// integrity against off-path tampering — the keys are derived from the
// Destination Connection ID in the clear header and a salt published in the
// RFC, so anyone on the path (and we are the endpoint) can decrypt them.
// That is what makes a QUIC JA4 possible without touching quic-go's
// internals: we decrypt our own copy of each Initial packet before quic-go
// processes the original.
//
// References: RFC 9000 §17.2.2 (Initial packet), RFC 9001 §5 (Initial
// protection), RFC 9369 (QUIC version 2).

const (
	quicVersion1 = 0x00000001
	quicVersion2 = 0x6b3343cf

	// quicMinInitialDatagram is the smallest UDP payload a client may carry
	// an Initial packet in (RFC 9000 §14.1). Servers must discard smaller
	// ones, so we can skip them without decrypting anything.
	quicMinInitialDatagram = 1200

	quicMaxConnIDLen = 20
)

var (
	quicSaltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	quicSaltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

var errNotInitial = errors.New("ja4: not a QUIC Initial packet")

// cryptoChunk is the payload of one CRYPTO frame: a slice of the client's
// handshake byte stream starting at offset.
type cryptoChunk struct {
	offset uint64
	data   []byte
}

// quicInitial is what we learn from one decrypted client Initial packet.
type quicInitial struct {
	version uint32
	dcid    []byte
	chunks  []cryptoChunk
}

// quicInitialKeys holds the client-side Initial packet protection keys for
// one Destination Connection ID.
type quicInitialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// hkdfExpandLabel is TLS 1.3's HKDF-Expand-Label (RFC 8446 §7.1) with an
// empty context, which is all QUIC Initial key derivation needs.
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func deriveQUICInitialKeys(version uint32, dcid []byte) (*quicInitialKeys, error) {
	salt, prefix := quicSaltV1, "quic "
	if version == quicVersion2 {
		salt, prefix = quicSaltV2, "quicv2 "
	}

	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, err
	}
	client, err := hkdfExpandLabel(initial, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, err := hkdfExpandLabel(client, prefix+"key", 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabel(client, prefix+"iv", 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := hkdfExpandLabel(client, prefix+"hp", 16)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	return &quicInitialKeys{aead: aead, iv: iv, hp: hp}, nil
}

// isQUICInitialType reports whether the long-header type bits of first mean
// "Initial" for version. Version 2 deliberately reshuffled the type codes
// (RFC 9369 §3.2) so that middleboxes could not ossify on version 1's.
func isQUICInitialType(version uint32, first byte) bool {
	packetType := (first >> 4) & 0x03
	switch version {
	case quicVersion1:
		return packetType == 0x00
	case quicVersion2:
		return packetType == 0x01
	}
	return false
}

// looksLikeQUICInitialDatagram is the cheap check done on every datagram
// before anything is copied or decrypted: a long header of a version we
// understand, carrying an Initial, in a datagram big enough to be legal.
// Everything on an established connection uses short headers and fails the
// first test.
func looksLikeQUICInitialDatagram(d []byte) bool {
	if len(d) < quicMinInitialDatagram || d[0]&0x80 == 0 {
		return false
	}
	version := binary.BigEndian.Uint32(d[1:5])
	return isQUICInitialType(version, d[0])
}

// parseQUICInitialDatagram decrypts every client Initial packet in a UDP
// datagram (a datagram may coalesce several QUIC packets, RFC 9000 §12.2)
// and returns their CRYPTO frames. It never modifies d.
func parseQUICInitialDatagram(d []byte) ([]quicInitial, error) {
	var out []quicInitial
	for len(d) > 0 {
		if d[0]&0x80 == 0 {
			break // short header: always last in a datagram
		}
		pkt, rest, err := splitLongHeaderPacket(d)
		if err != nil {
			break
		}
		if isQUICInitialType(binary.BigEndian.Uint32(d[1:5]), d[0]) {
			if in, err := decryptQUICInitial(pkt); err == nil {
				out = append(out, *in)
			}
		}
		d = rest
	}
	if len(out) == 0 {
		return nil, errNotInitial
	}
	return out, nil
}

// splitLongHeaderPacket returns the first long-header packet in d and what
// follows it.
func splitLongHeaderPacket(d []byte) (pkt, rest []byte, err error) {
	c := cursor{buf: d}
	first, _ := c.uint8()
	version, ok := c.uint32()
	if !ok || version == 0 { // version 0 is Version Negotiation: no length
		return nil, nil, errNotInitial
	}
	if version != quicVersion1 && version != quicVersion2 {
		return nil, nil, errNotInitial // unknown version: can't tell the layout
	}
	for range 2 { // DCID, then SCID
		n, ok := c.uint8()
		if !ok || n > quicMaxConnIDLen {
			return nil, nil, errNotInitial
		}
		if _, ok := c.take(int(n)); !ok {
			return nil, nil, errNotInitial
		}
	}
	packetType := (first >> 4) & 0x03
	isRetry := (version == quicVersion1 && packetType == 0x03) ||
		(version == quicVersion2 && packetType == 0x00)
	if isRetry {
		return d, nil, nil // Retry has no length and runs to the end
	}
	if isQUICInitialType(version, first) {
		tokenLen, ok := c.varint()
		if !ok || tokenLen > uint64(c.remaining()) {
			return nil, nil, errNotInitial
		}
		c.take(int(tokenLen))
	}
	length, ok := c.varint()
	if !ok || length > uint64(c.remaining()) {
		return nil, nil, errNotInitial
	}
	end := c.pos + int(length)
	return d[:end], d[end:], nil
}

// decryptQUICInitial removes header and packet protection from one client
// Initial packet (RFC 9001 §5.3, §5.4) and collects its CRYPTO frames.
func decryptQUICInitial(pkt []byte) (*quicInitial, error) {
	c := cursor{buf: pkt}
	first, _ := c.uint8()
	version, _ := c.uint32()
	dcidLen, _ := c.uint8()
	dcid, ok := c.take(int(dcidLen))
	if !ok {
		return nil, errNotInitial
	}
	scidLen, _ := c.uint8()
	if _, ok := c.take(int(scidLen)); !ok {
		return nil, errNotInitial
	}
	tokenLen, ok := c.varint()
	if !ok || tokenLen > uint64(c.remaining()) {
		return nil, errNotInitial
	}
	c.take(int(tokenLen))
	length, ok := c.varint()
	if !ok || length > uint64(c.remaining()) {
		return nil, errNotInitial
	}
	pnOffset := c.pos

	// Header protection samples 16 bytes starting 4 bytes past the start of
	// the packet number, whatever the packet number's real length.
	if pnOffset+4+16 > len(pkt) {
		return nil, errNotInitial
	}

	keys, err := deriveQUICInitialKeys(version, dcid)
	if err != nil {
		return nil, err
	}

	var mask [aes.BlockSize]byte
	keys.hp.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+4+16])

	// Unmask a private copy of the header; the datagram belongs to quic-go.
	pnLen := int((first^mask[0])&0x0f&0x03) + 1
	header := make([]byte, pnOffset+pnLen)
	copy(header, pkt[:pnOffset+pnLen])
	header[0] ^= mask[0] & 0x0f
	var pn uint64
	for i := range pnLen {
		header[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(header[pnOffset+i])
	}

	// Client Initial packet numbers start at 0 and stay tiny, so the
	// truncated packet number is the full one; no reconstruction needed.
	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	end := pnOffset + int(length)
	if end > len(pkt) || pnOffset+pnLen > end {
		return nil, errNotInitial
	}
	payload, err := keys.aead.Open(nil, nonce, pkt[pnOffset+pnLen:end], header)
	if err != nil {
		return nil, err
	}

	chunks, err := cryptoFrames(payload)
	if err != nil {
		return nil, err
	}
	return &quicInitial{version: version, dcid: append([]byte(nil), dcid...), chunks: chunks}, nil
}

// cryptoFrames walks a decrypted Initial payload and returns its CRYPTO
// frames. Only PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE are allowed
// in Initial packets (RFC 9000 §12.4); anything else ends the walk, keeping
// whatever was collected before it.
func cryptoFrames(p []byte) ([]cryptoChunk, error) {
	c := cursor{buf: p}
	var chunks []cryptoChunk
	for c.remaining() > 0 {
		frameType, ok := c.varint()
		if !ok {
			return chunks, nil
		}
		switch frameType {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK, ACK with ECN counts
			// largest, delay, range count, first range
			var rangeCount uint64
			for i := range 4 {
				v, ok := c.varint()
				if !ok {
					return chunks, nil
				}
				if i == 2 {
					rangeCount = v
				}
			}
			if rangeCount > uint64(c.remaining()) {
				return chunks, nil
			}
			for range 2 * rangeCount { // gap, length
				if _, ok := c.varint(); !ok {
					return chunks, nil
				}
			}
			if frameType == 0x03 {
				for range 3 { // ECT0, ECT1, ECN-CE
					if _, ok := c.varint(); !ok {
						return chunks, nil
					}
				}
			}
		case 0x06: // CRYPTO
			offset, ok1 := c.varint()
			n, ok2 := c.varint()
			if !ok1 || !ok2 || n > uint64(c.remaining()) {
				return chunks, nil
			}
			data, _ := c.take(int(n))
			chunks = append(chunks, cryptoChunk{offset: offset, data: data})
		default: // CONNECTION_CLOSE or a frame not allowed here
			return chunks, nil
		}
	}
	return chunks, nil
}

func (c *cursor) uint32() (uint32, bool) {
	b, ok := c.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

// varint reads a QUIC variable-length integer (RFC 9000 §16): the top two
// bits of the first byte give the encoded length, 1, 2, 4 or 8 bytes.
func (c *cursor) varint() (uint64, bool) {
	if c.remaining() < 1 {
		return 0, false
	}
	n := 1 << (c.buf[c.pos] >> 6)
	b, ok := c.take(n)
	if !ok {
		return 0, false
	}
	v := uint64(b[0] & 0x3f)
	for _, x := range b[1:] {
		v = v<<8 | uint64(x)
	}
	return v, true
}
