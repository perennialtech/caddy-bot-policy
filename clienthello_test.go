package botpolicy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// helloBuilder assembles ClientHello bytes for tests.
type helloBuilder struct {
	legacyVersion uint16
	cipherSuites  []uint16
	extensions    []byte
}

func (b *helloBuilder) extension(extType uint16, body []byte) *helloBuilder {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, extType)
	binary.Write(&buf, binary.BigEndian, uint16(len(body)))
	buf.Write(body)
	b.extensions = append(b.extensions, buf.Bytes()...)
	return b
}

// body returns the ClientHello message body, i.e. what follows the handshake
// header.
func (b *helloBuilder) body() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, b.legacyVersion)
	buf.Write(make([]byte, clientHelloRandomLen))
	buf.WriteByte(0) // empty session id

	binary.Write(&buf, binary.BigEndian, uint16(len(b.cipherSuites)*2))
	for _, cs := range b.cipherSuites {
		binary.Write(&buf, binary.BigEndian, cs)
	}

	buf.WriteByte(1) // one compression method
	buf.WriteByte(0) // null

	if len(b.extensions) > 0 {
		binary.Write(&buf, binary.BigEndian, uint16(len(b.extensions)))
		buf.Write(b.extensions)
	}
	return buf.Bytes()
}

// records wraps the hello in TLS handshake records, splitting the payload
// into chunks of at most chunk bytes (0 means a single record).
func (b *helloBuilder) records(chunk int) []byte {
	body := b.body()

	var handshake bytes.Buffer
	handshake.WriteByte(handshakeTypeClientHello)
	handshake.WriteByte(byte(len(body) >> 16))
	handshake.WriteByte(byte(len(body) >> 8))
	handshake.WriteByte(byte(len(body)))
	handshake.Write(body)

	payload := handshake.Bytes()
	if chunk <= 0 || chunk >= len(payload) {
		chunk = len(payload)
	}

	var out bytes.Buffer
	for len(payload) > 0 {
		n := min(chunk, len(payload))
		out.WriteByte(recordTypeHandshake)
		out.WriteByte(0x03)
		out.WriteByte(0x01)
		binary.Write(&out, binary.BigEndian, uint16(n))
		out.Write(payload[:n])
		payload = payload[n:]
	}
	return out.Bytes()
}

func alpnExtension(protocols ...string) []byte {
	var list bytes.Buffer
	for _, p := range protocols {
		list.WriteByte(byte(len(p)))
		list.WriteString(p)
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(list.Len()))
	buf.Write(list.Bytes())
	return buf.Bytes()
}

func supportedVersionsExtension(versions ...uint16) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(len(versions) * 2))
	for _, v := range versions {
		binary.Write(&buf, binary.BigEndian, v)
	}
	return buf.Bytes()
}

func signatureAlgorithmsExtension(algorithms ...uint16) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(len(algorithms)*2))
	for _, a := range algorithms {
		binary.Write(&buf, binary.BigEndian, a)
	}
	return buf.Bytes()
}

func fullHello() *helloBuilder {
	b := &helloBuilder{
		legacyVersion: 0x0303,
		cipherSuites:  []uint16{0x1a1a, 0x1301, 0x1302},
	}
	b.extension(extServerName, []byte{0x00, 0x05, 0x00, 0x00, 0x02, 'h', 'i'})
	b.extension(extALPN, alpnExtension("h2", "http/1.1"))
	b.extension(extSupportedVersions, supportedVersionsExtension(0x0a0a, 0x0304, 0x0303))
	b.extension(extSignatureAlgorithms, signatureAlgorithmsExtension(0x0403, 0x0804))
	return b
}

func TestParseClientHello(t *testing.T) {
	hello, err := parseClientHello(fullHello().body())
	if err != nil {
		t.Fatalf("parseClientHello() error = %v", err)
	}

	if hello.legacyVersion != 0x0303 {
		t.Errorf("legacyVersion = %#04x, want 0x0303", hello.legacyVersion)
	}
	if want := []uint16{0x1a1a, 0x1301, 0x1302}; !equalUint16(hello.cipherSuites, want) {
		t.Errorf("cipherSuites = %v, want %v", hello.cipherSuites, want)
	}
	want := []uint16{extServerName, extALPN, extSupportedVersions, extSignatureAlgorithms}
	if !equalUint16(hello.extensions, want) {
		t.Errorf("extensions = %v, want %v", hello.extensions, want)
	}
	if !hello.hasServerName {
		t.Error("hasServerName = false, want true")
	}
	if hello.firstALPN != "h2" {
		t.Errorf("firstALPN = %q, want %q", hello.firstALPN, "h2")
	}
	if want := []uint16{0x0a0a, 0x0304, 0x0303}; !equalUint16(hello.supportedVersions, want) {
		t.Errorf("supportedVersions = %v, want %v", hello.supportedVersions, want)
	}
	if want := []uint16{0x0403, 0x0804}; !equalUint16(hello.signatureAlgorithms, want) {
		t.Errorf("signatureAlgorithms = %v, want %v", hello.signatureAlgorithms, want)
	}
}

func TestParseClientHelloWithoutExtensions(t *testing.T) {
	b := &helloBuilder{legacyVersion: 0x0301, cipherSuites: []uint16{0x002f}}
	hello, err := parseClientHello(b.body())
	if err != nil {
		t.Fatalf("parseClientHello() error = %v", err)
	}
	if len(hello.extensions) != 0 {
		t.Errorf("extensions = %v, want none", hello.extensions)
	}
	if hello.hasServerName {
		t.Error("hasServerName = true, want false")
	}
}

func TestParseClientHelloTruncated(t *testing.T) {
	body := fullHello().body()

	// The prefix ending exactly where the extension block starts is a valid
	// extension-less hello rather than a truncation, so it is the one length
	// that must parse. Everything else has to be rejected instead of yielding
	// a partial fingerprint.
	extensionless := len((&helloBuilder{
		legacyVersion: 0x0303,
		cipherSuites:  []uint16{0x1a1a, 0x1301, 0x1302},
	}).body())

	for n := 0; n < len(body); n++ {
		_, err := parseClientHello(body[:n])
		if n == extensionless {
			if err != nil {
				t.Fatalf("parseClientHello(body[:%d]) error = %v, want a valid extension-less hello", n, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("parseClientHello(body[:%d]) succeeded, want error", n)
		}
	}
}

func TestHandshakeBodySingleRecord(t *testing.T) {
	raw := fullHello().records(0)
	body, need, err := handshakeBody(raw)
	if err != nil {
		t.Fatalf("handshakeBody() error = %v (need %d)", err, need)
	}
	if !bytes.Equal(body, fullHello().body()) {
		t.Error("handshakeBody() returned a body that differs from the hello")
	}
}

// TestHandshakeBodyFragmented covers a hello split across several TLS
// records, which is legal and does happen with large post-quantum hellos.
func TestHandshakeBodyFragmented(t *testing.T) {
	raw := fullHello().records(16)
	body, need, err := handshakeBody(raw)
	if err != nil {
		t.Fatalf("handshakeBody() error = %v (need %d)", err, need)
	}
	if !bytes.Equal(body, fullHello().body()) {
		t.Error("handshakeBody() did not reassemble the fragmented hello")
	}
}

func TestHandshakeBodyAsksForMoreWhenShort(t *testing.T) {
	raw := fullHello().records(0)
	_, need, err := handshakeBody(raw[:10])
	if err == nil {
		t.Fatal("handshakeBody() on a short buffer succeeded, want error")
	}
	if need <= 10 {
		t.Errorf("need = %d, want more than the 10 bytes supplied", need)
	}
}

func TestHandshakeBodyRejectsNonTLS(t *testing.T) {
	_, need, err := handshakeBody([]byte("GET / HTTP/1.1\r\n\r\n"))
	if err == nil {
		t.Fatal("handshakeBody() accepted plain HTTP, want error")
	}
	if need != 0 {
		t.Errorf("need = %d, want 0 — plain HTTP is never going to become a hello", need)
	}
}

func equalUint16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
