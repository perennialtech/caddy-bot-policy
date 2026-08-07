package botpolicy

// This file is the package's only exported entry point to the fingerprint
// itself. Inside Caddy the JA4 is computed by the listener wrapper and never
// passed around as a value, but building and auditing a catalogue of known
// fingerprints means computing one from a captured ClientHello outside of a
// server — see cmd/ja4probe.

// Fingerprint computes the JA4 of the ClientHello at the start of record,
// which is the raw bytes read from a TCP connection: one or more complete TLS
// records, starting at the record header. Trailing bytes beyond the
// ClientHello are ignored.
//
// It returns an error when the bytes are not a ClientHello at all or when the
// message is incomplete, so callers that stream from a connection can keep
// reading and retry rather than treat a short read as a parse failure.
//
// The transport is TCP: QUIC hellos do not arrive as bare TLS records, and
// the listener wrapper this package installs only ever sees TCP.
func Fingerprint(record []byte) (string, error) {
	body, _, err := handshakeBody(record)
	if err != nil {
		return "", err
	}
	ch, err := parseClientHello(body)
	if err != nil {
		return "", err
	}
	return ch.ja4(transportTCP), nil
}
