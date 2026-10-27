package botpolicy

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The RFC test vectors: RFC 9001 Appendix A (QUIC v1) and RFC 9369
// Appendix A (QUIC v2) both protect the same client Initial, a 245-byte
// CRYPTO frame plus PADDING, with Destination Connection ID 8394c8f03e515708
// and packet number 2.
var rfcDCID = mustHex("8394c8f03e515708")

// rfcHelloJA4 was computed independently, with a reference implementation
// that reproduces all of FoxIO's own TLS test vectors, from the ClientHello
// in RFC 9001 A.2 (two ciphers, eleven extensions, ALPN "alpn").
const rfcHelloJA4 = "q13d0211an_62ed6f6ca7ad_4d634acda6c0"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		panic(err)
	}
	return b
}

func readHex(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return mustHex(string(raw))
}

// sealInitial builds a protected client Initial packet: the inverse of
// decryptQUICInitial, written independently so the two check each other.
// The packet number is always encoded in 4 bytes, as in the RFC vectors.
func sealInitial(t *testing.T, version uint32, dcid, scid []byte, pn uint32, payload []byte) []byte {
	t.Helper()
	keys, err := deriveQUICInitialKeys(version, dcid)
	if err != nil {
		t.Fatal(err)
	}
	typeBits := byte(0x00)
	if version == quicVersion2 {
		typeBits = 0x01
	}
	header := []byte{0xc0 | typeBits<<4 | 0x03}
	header = binary.BigEndian.AppendUint32(header, version)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00) // empty token
	length := 4 + len(payload) + 16
	header = binary.BigEndian.AppendUint16(header, 0x4000|uint16(length))
	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, pn)

	nonce := append([]byte(nil), keys.iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(uint64(pn) >> (8 * i))
	}
	ciphertext := keys.aead.Seal(nil, nonce, payload, header)

	var mask [aes.BlockSize]byte
	keys.hp.Encrypt(mask[:], ciphertext[:16]) // sample starts at pnOffset+4
	header[0] ^= mask[0] & 0x0f
	for i := range 4 {
		header[pnOffset+i] ^= mask[1+i]
	}
	return append(header, ciphertext...)
}

// cryptoFrame encodes a CRYPTO frame with 4-byte varints for both fields.
func cryptoFrame(offset uint64, data []byte) []byte {
	f := []byte{0x06}
	f = binary.BigEndian.AppendUint32(f, 0x80000000|uint32(offset))
	f = binary.BigEndian.AppendUint32(f, 0x80000000|uint32(len(data)))
	return append(f, data...)
}

// padTo appends PADDING so the protected packet fills a 1200-byte datagram.
func padTo(payload []byte, dcidLen int) []byte {
	overhead := 1 + 4 + 1 + dcidLen + 1 + 1 + 2 + 4 + 16
	if n := quicMinInitialDatagram - overhead - len(payload); n > 0 {
		payload = append(payload, make([]byte, n)...)
	}
	return payload
}

func TestDeriveQUICInitialKeysMatchesRFC(t *testing.T) {
	for _, tc := range []struct {
		version uint32
		iv, hp  string
	}{
		{quicVersion1, "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{quicVersion2, "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
	} {
		keys, err := deriveQUICInitialKeys(tc.version, rfcDCID)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(keys.iv); got != tc.iv {
			t.Errorf("version %#x: iv %s, want %s", tc.version, got, tc.iv)
		}
		// crypto/cipher does not expose keys; compare the HP key by its output.
		// The AEAD key is covered end to end by TestSealInitialReproducesRFC.
		var want, got [aes.BlockSize]byte
		hp, _ := aes.NewCipher(mustHex(tc.hp))
		hp.Encrypt(want[:], make([]byte, 16))
		keys.hp.Encrypt(got[:], make([]byte, 16))
		if want != got {
			t.Errorf("version %#x: hp key does not match RFC", tc.version)
		}
	}
}

// TestSealInitialReproducesRFC proves the test helper (and so the key
// schedule both directions share) is byte-for-byte right before the other
// tests lean on it.
func TestSealInitialReproducesRFC(t *testing.T) {
	payload := padTo(readHex(t, "rfc_client_initial_payload.hex"), len(rfcDCID))
	for version, file := range map[uint32]string{
		quicVersion1: "rfc_client_initial_v1.hex",
		quicVersion2: "rfc_client_initial_v2.hex",
	} {
		got := sealInitial(t, version, rfcDCID, nil, 2, payload)
		if want := readHex(t, file); !bytes.Equal(got, want) {
			t.Errorf("version %#x: sealed packet differs from RFC vector", version)
		}
	}
}

func TestDecryptRFCClientInitial(t *testing.T) {
	wantHello := readHex(t, "rfc_client_initial_payload.hex")[4:] // skip CRYPTO frame header
	for version, file := range map[uint32]string{
		quicVersion1: "rfc_client_initial_v1.hex",
		quicVersion2: "rfc_client_initial_v2.hex",
	} {
		initials, err := parseQUICInitialDatagram(readHex(t, file))
		if err != nil {
			t.Fatalf("version %#x: %v", version, err)
		}
		if len(initials) != 1 || len(initials[0].chunks) != 1 {
			t.Fatalf("version %#x: got %d packets, want 1 with 1 CRYPTO frame", version, len(initials))
		}
		in := initials[0]
		if in.version != version || !bytes.Equal(in.dcid, rfcDCID) {
			t.Errorf("version %#x: header parsed as version %#x dcid %x", version, in.version, in.dcid)
		}
		if ch := in.chunks[0]; ch.offset != 0 || !bytes.Equal(ch.data, wantHello) {
			t.Errorf("version %#x: CRYPTO data does not match the RFC ClientHello", version)
		}
	}
}

func TestDecryptDoesNotModifyDatagram(t *testing.T) {
	d := readHex(t, "rfc_client_initial_v1.hex")
	orig := bytes.Clone(d)
	if _, err := parseQUICInitialDatagram(d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d, orig) {
		t.Fatal("parsing modified the datagram quic-go is about to read")
	}
}

func newTestSniffer() (*quicSniffer, *idleStore) {
	store := newIdleStore(time.Hour, 1000)
	return newQUICSniffer(defaultMaxCaptureBytes, store), store
}

func TestSnifferRFCInitial(t *testing.T) {
	for _, file := range []string{"rfc_client_initial_v1.hex", "rfc_client_initial_v2.hex"} {
		s, store := newTestSniffer()
		s.observe("192.0.2.1:4433", readHex(t, file))
		if got := store.get("192.0.2.1:4433"); got != rfcHelloJA4 {
			t.Errorf("%s: fingerprint %q, want %q", file, got, rfcHelloJA4)
		}
	}
}

// TestSnifferReassemblesScatteredHello mirrors what Chrome does: a hello too
// big for one packet, cut into many CRYPTO frames, shuffled, and spread over
// several datagrams that may themselves arrive out of order.
func TestSnifferReassemblesScatteredHello(t *testing.T) {
	b := fullHello()
	b.extension(0x0015, make([]byte, 2500)) // padding: force several packets
	hello := b.body()
	msg := append([]byte{handshakeTypeClientHello, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)

	parsed, err := parseClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	want := parsed.ja4(transportQUIC)

	rng := rand.New(rand.NewPCG(1, 2))
	var frames [][]byte
	for off := 0; off < len(msg); {
		n := min(50+rng.IntN(300), len(msg)-off)
		frames = append(frames, cryptoFrame(uint64(off), msg[off:off+n]))
		off += n
	}
	rng.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })

	dcid := mustHex("0102030405060708")
	var datagrams [][]byte
	for pn := uint32(0); len(frames) > 0; pn++ {
		var payload []byte
		for len(frames) > 0 && len(payload)+len(frames[0]) < 1100 {
			payload = append(payload, frames[0]...)
			frames = frames[1:]
		}
		datagrams = append(datagrams, sealInitial(t, quicVersion1, dcid, nil, pn, padTo(payload, len(dcid))))
	}
	if len(datagrams) < 3 {
		t.Fatalf("test setup: hello fit in %d datagrams, want at least 3", len(datagrams))
	}
	rng.Shuffle(len(datagrams), func(i, j int) { datagrams[i], datagrams[j] = datagrams[j], datagrams[i] })

	s, store := newTestSniffer()
	for i, d := range datagrams {
		if i < len(datagrams)-1 && store.get("192.0.2.1:5000") != "" {
			t.Fatal("fingerprint recorded before the hello was complete")
		}
		s.observe("192.0.2.1:5000", d)
	}
	if got := store.get("192.0.2.1:5000"); got != want {
		t.Fatalf("fingerprint %q, want %q", got, want)
	}
	if !strings.HasPrefix(want, "q") {
		t.Fatalf("QUIC fingerprint %q must start with q", want)
	}
	if len(s.pending) != 0 {
		t.Errorf("%d pending hellos left after completion", len(s.pending))
	}
}

// TestSnifferCoalescedPackets covers a datagram carrying the Initial
// followed by another long-header packet, as clients do with 0-RTT.
func TestSnifferCoalescedPackets(t *testing.T) {
	payload := padTo(readHex(t, "rfc_client_initial_payload.hex"), len(rfcDCID))
	initial := sealInitial(t, quicVersion1, rfcDCID, nil, 2, payload)
	zeroRTT := []byte{0xd0 | 0x03} // v1 0-RTT long header
	zeroRTT = binary.BigEndian.AppendUint32(zeroRTT, quicVersion1)
	zeroRTT = append(zeroRTT, byte(len(rfcDCID)))
	zeroRTT = append(zeroRTT, rfcDCID...)
	zeroRTT = append(zeroRTT, 0x00, 0x40, 0x20) // no SCID, length 32
	zeroRTT = append(zeroRTT, make([]byte, 32)...)

	s, store := newTestSniffer()
	s.observe("192.0.2.1:6000", append(initial, zeroRTT...))
	if got := store.get("192.0.2.1:6000"); got != rfcHelloJA4 {
		t.Fatalf("fingerprint %q, want %q", got, rfcHelloJA4)
	}
}

// TestSnifferNewConnectionClearsOldFingerprint checks a fingerprint cannot
// outlive its connection and get attached to the next one from the same
// address, even when the new connection's hello is unreadable.
func TestSnifferNewConnectionClearsOldFingerprint(t *testing.T) {
	s, store := newTestSniffer()
	addr := "192.0.2.1:7000"
	s.observe(addr, readHex(t, "rfc_client_initial_v1.hex"))
	if store.get(addr) == "" {
		t.Fatal("setup: no fingerprint for the first connection")
	}

	// A new connection (new DCID) whose first packet carries only the
	// start of the hello.
	msg := []byte{handshakeTypeClientHello, 0x00, 0x10, 0x00, 0x03, 0x03}
	d := sealInitial(t, quicVersion1, mustHex("aabbccddeeff0011"), nil, 0, padTo(cryptoFrame(0, msg), 8))
	s.observe(addr, d)
	if got := store.get(addr); got != "" {
		t.Fatalf("new connection inherited the old fingerprint %q", got)
	}
}

func TestSnifferIgnoresNonInitialTraffic(t *testing.T) {
	s, store := newTestSniffer()
	short := make([]byte, 1300) // short header: first bit clear
	short[0] = 0x40
	s.observe("192.0.2.1:1", short)

	small := readHex(t, "rfc_client_initial_v1.hex")[:1199] // below the legal minimum
	s.observe("192.0.2.1:2", small)

	unknownVersion := readHex(t, "rfc_client_initial_v1.hex")
	unknownVersion[4] = 0x02
	s.observe("192.0.2.1:3", unknownVersion)

	tampered := readHex(t, "rfc_client_initial_v1.hex")
	tampered[len(tampered)-1] ^= 1 // fails AEAD authentication
	s.observe("192.0.2.1:4", tampered)

	if n := store.len(); n != 0 {
		t.Fatalf("%d fingerprints recorded from non-Initial or invalid datagrams", n)
	}
	if n := len(s.pending); n != 0 {
		t.Fatalf("%d pending hellos created from non-Initial or invalid datagrams", n)
	}
}

func TestSnifferBoundsPendingState(t *testing.T) {
	s, _ := newTestSniffer()
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }

	// Partial hellos from more addresses than the cap allows.
	msg := []byte{handshakeTypeClientHello, 0x00, 0x10, 0x00}
	d := sealInitial(t, quicVersion1, mustHex("0102030405060708"), nil, 0, padTo(cryptoFrame(0, msg), 8))
	for i := range quicMaxPendingHellos + 100 {
		s.observe("198.51.100.1:"+strconv.Itoa(1024+i), d)
	}
	if n := len(s.pending); n != quicMaxPendingHellos {
		t.Fatalf("%d pending hellos, want the cap of %d", n, quicMaxPendingHellos)
	}

	// Once they expire, new ones are accepted again.
	now = now.Add(quicPendingTTL + 2*time.Second)
	s.observe("203.0.113.1:1", d)
	if _, ok := s.pending["203.0.113.1:1"]; !ok {
		t.Fatal("expired pending hellos were not swept to make room")
	}
}

func TestSnifferRejectsOversizedHello(t *testing.T) {
	s, store := newTestSniffer()
	s.maxHelloBytes = 1024
	b := fullHello()
	b.extension(0x0015, make([]byte, 1500))
	hello := b.body()
	msg := append([]byte{handshakeTypeClientHello, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	dcid := mustHex("0102030405060708")
	s.observe("192.0.2.1:1", sealInitial(t, quicVersion1, dcid, nil, 0, padTo(cryptoFrame(0, msg[:900]), 8)))
	s.observe("192.0.2.1:1", sealInitial(t, quicVersion1, dcid, nil, 1, padTo(cryptoFrame(900, msg[900:]), 8)))
	if store.len() != 0 || len(s.pending) != 0 {
		t.Fatal("hello larger than max_capture_bytes was kept")
	}
}

func TestIdleStore(t *testing.T) {
	now := time.Unix(0, 0)
	s := newIdleStore(time.Minute, 2)
	s.now = func() time.Time { return now }

	s.set("a", "fa")
	s.set("b", "fb")
	s.set("c", "fc") // full of live entries: fails open
	if s.get("c") != "" {
		t.Error("entry stored beyond the cap")
	}

	now = now.Add(50 * time.Second)
	if s.get("a") != "fa" { // refreshes a
		t.Fatal("live entry missing")
	}
	now = now.Add(50 * time.Second) // b is now idle for 100s, a for 50s
	if s.get("b") != "" {
		t.Error("idle entry not expired")
	}
	if s.get("a") != "fa" {
		t.Error("refreshed entry expired")
	}
	now = now.Add(2 * time.Second)
	s.set("c", "fc") // b expired, so there is room now
	if s.get("c") != "fc" {
		t.Error("expired entries did not free up room")
	}
}

func FuzzParseQUICInitialDatagram(f *testing.F) {
	raw, err := os.ReadFile("testdata/rfc_client_initial_v1.hex")
	if err == nil {
		f.Add(mustHex(string(raw)))
	}
	f.Add(make([]byte, 1200))
	f.Fuzz(func(t *testing.T, d []byte) {
		s, _ := newTestSniffer()
		s.observe("192.0.2.1:1", d) // must never panic
	})
}
