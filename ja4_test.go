package botpolicy

import (
	"strings"
	"testing"
)

func TestIsGREASE(t *testing.T) {
	// The 16 values reserved by RFC 8701.
	grease := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range grease {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = false, want true", v)
		}
	}

	// Real values that are close enough to catch a sloppy mask: TLS_AES_128_GCM_SHA256,
	// an extension type, and two near-misses on each half of the pattern.
	notGrease := []uint16{0x1301, 0x002b, 0x0a0b, 0x1a0a, 0x0b0b, 0xabab}
	for _, v := range notGrease {
		if isGREASE(v) {
			t.Errorf("isGREASE(%#04x) = true, want false", v)
		}
	}
}

func TestTLSVersionCode(t *testing.T) {
	cases := map[uint16]string{
		0x0304: "13",
		0x0303: "12",
		0x0302: "11",
		0x0301: "10",
		0x0300: "s3",
		0x0002: "s2",
		0x9999: "00", // unknown
	}
	for version, want := range cases {
		if got := tlsVersionCode(version); got != want {
			t.Errorf("tlsVersionCode(%#04x) = %q, want %q", version, got, want)
		}
	}
}

func TestClientHelloVersionPrefersSupportedVersions(t *testing.T) {
	// A TLS 1.3 client freezes legacy_version at 0x0303 and advertises the
	// real thing in supported_versions, GREASE included.
	ch := &clientHello{
		legacyVersion:     0x0303,
		supportedVersions: []uint16{0x1a1a, 0x0304, 0x0303},
	}
	if got := ch.version(); got != 0x0304 {
		t.Errorf("version() = %#04x, want 0x0304", got)
	}

	// Without the extension the legacy field is all there is.
	ch = &clientHello{legacyVersion: 0x0303}
	if got := ch.version(); got != 0x0303 {
		t.Errorf("version() = %#04x, want 0x0303", got)
	}

	// A hello offering nothing but GREASE must not report a GREASE version.
	ch = &clientHello{legacyVersion: 0x0301, supportedVersions: []uint16{0x3a3a}}
	if got := ch.version(); got != 0x0301 {
		t.Errorf("version() = %#04x, want 0x0301", got)
	}
}

func TestAlpnCode(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{
		{"", "00"},         // no ALPN offered
		{"h2", "h2"},       // the common case
		{"http/1.1", "h1"}, // first and last of the whole string
		{"h", "hh"},        // single character is doubled
		{"h3", "h3"},       //
		{"\x00\xff", "0f"}, // non-alphanumeric: first and last of the hex
		{"a\xff", "6f"},    // last byte non-alphanumeric -> hex of "61ff"
	}
	for _, c := range cases {
		if got := alpnCode(c.alpn); got != c.want {
			t.Errorf("alpnCode(%q) = %q, want %q", c.alpn, got, c.want)
		}
	}
}

func TestTwoDigitCountSaturates(t *testing.T) {
	cases := map[int]string{0: "00", 5: "05", 42: "42", 99: "99", 100: "99", 1000: "99"}
	for n, want := range cases {
		if got := twoDigitCount(n); got != want {
			t.Errorf("twoDigitCount(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestJA4cList pins the exact string that gets hashed into the third part of
// the fingerprint. This is where the spec is actually encoded — extensions
// sorted, SNI and ALPN dropped, signature algorithms appended in wire order —
// so the expectations are written out by hand rather than derived.
func TestJA4cList(t *testing.T) {
	extensions := []uint16{
		extALPN,       // dropped: represented in part "a" instead
		0x002b,        //
		extServerName, // dropped: represented in part "a" instead
		0x0017,        //
		extSignatureAlgorithms,
	}
	signatureAlgorithms := []uint16{0x0403, 0x0804, 0x0401}

	got := ja4cList(extensions, signatureAlgorithms)
	want := "000d,0017,002b_0403,0804,0401"
	if got != want {
		t.Errorf("ja4cList() = %q, want %q", got, want)
	}

	// No signature algorithms means no trailing underscore at all.
	got = ja4cList([]uint16{0x0017, 0x002b}, nil)
	want = "0017,002b"
	if got != want {
		t.Errorf("ja4cList() without sigalgs = %q, want %q", got, want)
	}

	// A hello carrying only SNI and ALPN has nothing left to hash.
	if got := ja4cList([]uint16{extServerName, extALPN}, nil); got != "" {
		t.Errorf("ja4cList() with only SNI+ALPN = %q, want empty", got)
	}
}

func TestHexListSorted(t *testing.T) {
	got := hexList(sortedCopy([]uint16{0x1302, 0x1301, 0xc02b}))
	want := "1301,1302,c02b"
	if got != want {
		t.Errorf("hexList(sorted) = %q, want %q", got, want)
	}
}

func TestTruncatedHashEmptyIsZeros(t *testing.T) {
	if got := truncatedHash(""); got != emptyListHash {
		t.Errorf("truncatedHash(\"\") = %q, want %q", got, emptyListHash)
	}
	got := truncatedHash("1301,1302")
	if len(got) != 12 {
		t.Fatalf("truncatedHash() length = %d, want 12", len(got))
	}
	if got == emptyListHash {
		t.Error("truncatedHash() of a non-empty list returned the empty placeholder")
	}
}

// TestJA4Structure checks the assembled fingerprint end to end: the readable
// part exactly, and the two hashes for shape and for agreement with the lists
// they are supposed to summarize.
func TestJA4Structure(t *testing.T) {
	ch := &clientHello{
		legacyVersion:       0x0303,
		cipherSuites:        []uint16{0x1a1a, 0x1301, 0x1302, 0xc02b}, // one GREASE
		extensions:          []uint16{0x0a0a, extServerName, extALPN, extSupportedVersions, extSignatureAlgorithms},
		hasServerName:       true,
		firstALPN:           "h2",
		supportedVersions:   []uint16{0x0304, 0x0303},
		signatureAlgorithms: []uint16{0x0403, 0x0804},
	}

	got := ch.ja4(transportTCP)
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("ja4() = %q, want three underscore-separated parts", got)
	}

	// t=TCP, 13=TLS1.3, d=SNI present, 03 ciphers after dropping GREASE,
	// 04 extensions after dropping GREASE (SNI and ALPN still counted), h2=ALPN.
	if want := "t13d0304h2"; parts[0] != want {
		t.Errorf("ja4() part a = %q, want %q", parts[0], want)
	}
	if want := truncatedHash("1301,1302,c02b"); parts[1] != want {
		t.Errorf("ja4() part b = %q, want %q", parts[1], want)
	}
	if want := truncatedHash("000d,002b_0403,0804"); parts[2] != want {
		t.Errorf("ja4() part c = %q, want %q", parts[2], want)
	}
}

func TestJA4EmptyListsUseZeroPlaceholder(t *testing.T) {
	ch := &clientHello{legacyVersion: 0x0301}
	got := ch.ja4(transportTCP)
	want := "t10i0000" + "00" + "_" + emptyListHash + "_" + emptyListHash
	if got != want {
		t.Errorf("ja4() = %q, want %q", got, want)
	}
}

func TestJA4QUICTransportPrefix(t *testing.T) {
	ch := &clientHello{legacyVersion: 0x0303, supportedVersions: []uint16{0x0304}}
	if got := ch.ja4(transportQUIC); got[0] != 'q' {
		t.Errorf("ja4(quic) = %q, want a leading 'q'", got)
	}
}

func TestJA4BindingIgnoresResumptionOnlyExtensions(t *testing.T) {
	full := &clientHello{
		legacyVersion: 0x0303, supportedVersions: []uint16{0x0304},
		cipherSuites:  []uint16{0x1301, 0x1302},
		extensions:    []uint16{extServerName, extSupportedVersions, extSignatureAlgorithms, extALPN, extPadding},
		hasServerName: true, firstALPN: "h2", signatureAlgorithms: []uint16{0x0403, 0x0804},
	}
	resumed := *full
	resumed.extensions = []uint16{extServerName, extSupportedVersions, extSignatureAlgorithms, extALPN, extPreSharedKey, extEarlyData}
	for _, transport := range []byte{transportTCP, transportQUIC} {
		if full.ja4(transport) == resumed.ja4(transport) {
			t.Fatalf("%c: exact JA4 unexpectedly ignored changed extensions", transport)
		}
		if a, b := full.ja4Bind(transport), resumed.ja4Bind(transport); a != b {
			t.Fatalf("%c: stable binding differs across resumption: %s vs %s", transport, a, b)
		}
		other := resumed
		other.firstALPN = "http/1.1"
		if other.ja4Bind(transport) == full.ja4Bind(transport) {
			t.Fatalf("%c: binding should still distinguish ALPN profiles", transport)
		}
	}
}
