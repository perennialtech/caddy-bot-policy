package botpolicy

import "errors"

// TLS record and handshake framing constants (RFC 8446 §5.1, §4).
const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01

	recordHeaderLen    = 5 // type(1) + version(2) + length(2)
	handshakeHeaderLen = 4 // type(1) + length(3)

	clientHelloRandomLen = 32
)

// errMalformed means the bytes we were handed are not a ClientHello we can
// read. It is never fatal: the connection is handed to the TLS stack
// untouched and the request simply ends up without a fingerprint.
var errMalformed = errors.New("ja4: malformed client hello")

// clientHello holds the few ClientHello fields JA4 is computed from. Anything
// not needed for the fingerprint (random, session id, compression methods) is
// skipped during parsing rather than stored.
type clientHello struct {
	// legacyVersion is the version in the handshake header. Frozen at 0x0303
	// by TLS 1.3 clients; see clientHello.version.
	legacyVersion uint16

	cipherSuites []uint16

	// extensions holds extension types in wire order, GREASE included. The
	// order is kept because the count in part "a" is taken before sorting.
	extensions []uint16

	hasServerName bool

	// firstALPN is the first protocol offered in the ALPN extension, empty
	// when the client offered none.
	firstALPN string

	supportedVersions   []uint16
	signatureAlgorithms []uint16
}

// parseClientHello reads the body of a ClientHello handshake message, i.e.
// what follows the four-byte handshake header.
func parseClientHello(body []byte) (*clientHello, error) {
	c := cursor{buf: body}
	ch := &clientHello{}

	var ok bool
	if ch.legacyVersion, ok = c.uint16(); !ok {
		return nil, errMalformed
	}
	if _, ok = c.skip(clientHelloRandomLen); !ok {
		return nil, errMalformed
	}

	sessionIDLen, ok := c.uint8()
	if !ok {
		return nil, errMalformed
	}
	if _, ok = c.skip(int(sessionIDLen)); !ok {
		return nil, errMalformed
	}

	cipherSuitesLen, ok := c.uint16()
	if !ok {
		return nil, errMalformed
	}
	cipherSuites, ok := c.take(int(cipherSuitesLen))
	if !ok {
		return nil, errMalformed
	}
	if ch.cipherSuites, ok = uint16List(cipherSuites); !ok {
		return nil, errMalformed
	}

	compressionLen, ok := c.uint8()
	if !ok {
		return nil, errMalformed
	}
	if _, ok = c.skip(int(compressionLen)); !ok {
		return nil, errMalformed
	}

	// Extensions are optional on the wire: a pre-TLS-1.2 hello may simply end
	// here, and that is a valid fingerprint with zero extensions.
	if c.remaining() == 0 {
		return ch, nil
	}

	extensionsLen, ok := c.uint16()
	if !ok {
		return nil, errMalformed
	}
	extensions, ok := c.take(int(extensionsLen))
	if !ok {
		return nil, errMalformed
	}
	if err := ch.parseExtensions(extensions); err != nil {
		return nil, err
	}

	return ch, nil
}

// parseExtensions walks the extension block, recording every type and
// decoding the four extensions whose contents feed the fingerprint.
func (ch *clientHello) parseExtensions(b []byte) error {
	c := cursor{buf: b}
	for c.remaining() > 0 {
		extType, ok := c.uint16()
		if !ok {
			return errMalformed
		}
		extLen, ok := c.uint16()
		if !ok {
			return errMalformed
		}
		data, ok := c.take(int(extLen))
		if !ok {
			return errMalformed
		}

		ch.extensions = append(ch.extensions, extType)

		switch extType {
		case extServerName:
			// Only presence matters for JA4; the name itself is not part of
			// the fingerprint.
			ch.hasServerName = true

		case extALPN:
			ch.firstALPN = firstALPNProtocol(data)

		case extSupportedVersions:
			// A one-byte length prefix, then the version list.
			vc := cursor{buf: data}
			listLen, ok := vc.uint8()
			if !ok {
				return errMalformed
			}
			list, ok := vc.take(int(listLen))
			if !ok {
				return errMalformed
			}
			if ch.supportedVersions, ok = uint16List(list); !ok {
				return errMalformed
			}

		case extSignatureAlgorithms:
			// A two-byte length prefix, then the algorithm list.
			sc := cursor{buf: data}
			listLen, ok := sc.uint16()
			if !ok {
				return errMalformed
			}
			list, ok := sc.take(int(listLen))
			if !ok {
				return errMalformed
			}
			if ch.signatureAlgorithms, ok = uint16List(list); !ok {
				return errMalformed
			}
		}
	}
	return nil
}

// firstALPNProtocol returns the first protocol name in an ALPN extension
// body, or "" if the body is malformed or empty. A malformed ALPN is not
// worth failing the whole parse over: the rest of the hello still yields a
// usable fingerprint, just with "00" for the ALPN characters.
func firstALPNProtocol(b []byte) string {
	c := cursor{buf: b}
	listLen, ok := c.uint16()
	if !ok {
		return ""
	}
	list, ok := c.take(int(listLen))
	if !ok {
		return ""
	}

	lc := cursor{buf: list}
	nameLen, ok := lc.uint8()
	if !ok {
		return ""
	}
	name, ok := lc.take(int(nameLen))
	if !ok {
		return ""
	}
	return string(name)
}

// handshakeBody extracts the body of the first handshake message in buf,
// which may be spread across several TLS records.
//
// It returns the number of bytes that still need to be buffered when buf is
// too short, so the caller can peek further instead of guessing. need is 0
// when the message is complete or when the bytes cannot be a ClientHello at
// all (plain HTTP on the same port, for instance), in which case err says
// which.
func handshakeBody(buf []byte) (body []byte, need int, err error) {
	var assembled []byte
	consumed := 0

	for {
		if len(buf) < consumed+recordHeaderLen {
			return nil, consumed + recordHeaderLen, errMalformed
		}

		header := buf[consumed : consumed+recordHeaderLen]
		if header[0] != recordTypeHandshake {
			// Not a TLS handshake at all — nothing to wait for.
			return nil, 0, errMalformed
		}

		recordLen := int(header[3])<<8 | int(header[4])
		recordEnd := consumed + recordHeaderLen + recordLen
		if len(buf) < recordEnd {
			return nil, recordEnd, errMalformed
		}

		assembled = append(assembled, buf[consumed+recordHeaderLen:recordEnd]...)
		consumed = recordEnd

		if len(assembled) < handshakeHeaderLen {
			continue // header split across records; keep reading
		}
		if assembled[0] != handshakeTypeClientHello {
			return nil, 0, errMalformed
		}

		messageLen := int(assembled[1])<<16 | int(assembled[2])<<8 | int(assembled[3])
		if len(assembled) >= handshakeHeaderLen+messageLen {
			return assembled[handshakeHeaderLen : handshakeHeaderLen+messageLen], 0, nil
		}
		// The message continues in the next record. Ask for one more record
		// header so the caller makes progress rather than spinning.
		if len(buf) < consumed+recordHeaderLen {
			return nil, consumed + recordHeaderLen, errMalformed
		}
	}
}

// uint16List reinterprets an even-length byte slice as big-endian uint16s.
func uint16List(b []byte) ([]uint16, bool) {
	if len(b)%2 != 0 {
		return nil, false
	}
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out, true
}

// cursor is a bounds-checked reader over a byte slice. Every method reports
// success rather than panicking, because all of this parses bytes that an
// unauthenticated client controls.
type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) remaining() int { return len(c.buf) - c.pos }

func (c *cursor) uint8() (uint8, bool) {
	if c.remaining() < 1 {
		return 0, false
	}
	v := c.buf[c.pos]
	c.pos++
	return v, true
}

func (c *cursor) uint16() (uint16, bool) {
	if c.remaining() < 2 {
		return 0, false
	}
	v := uint16(c.buf[c.pos])<<8 | uint16(c.buf[c.pos+1])
	c.pos += 2
	return v, true
}

func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || c.remaining() < n {
		return nil, false
	}
	v := c.buf[c.pos : c.pos+n]
	c.pos += n
	return v, true
}

func (c *cursor) skip(n int) (struct{}, bool) {
	_, ok := c.take(n)
	return struct{}{}, ok
}
