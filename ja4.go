package botpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// This file implements the JA4 TLS client fingerprint as specified by FoxIO
// (https://github.com/FoxIO-LLC/ja4). The fingerprint has three parts joined
// by underscores, "a_b_c":
//
//	a: <transport><tls version><sni><cipher count><extension count><alpn>
//	b: first 12 hex chars of the SHA-256 of the sorted cipher suite list
//	c: first 12 hex chars of the SHA-256 of the sorted extension list, plus
//	   the signature algorithms in wire order
//
// The point of the design is that "a" stays human-readable while "b" and "c"
// compress two long lists into a fixed width. Sorting "b" and "c" is what
// makes the fingerprint survive the deliberate shuffling that some TLS
// stacks apply to cipher and extension order.

// TLS extension identifiers this package needs to treat specially.
const (
	extServerName          = 0x0000
	extSignatureAlgorithms = 0x000d
	extALPN                = 0x0010
	extSupportedVersions   = 0x002b
	extPadding             = 0x0015
	extPreSharedKey        = 0x0029
	extEarlyData           = 0x002a
)

// Transport prefixes: JA4 distinguishes fingerprints taken over TCP from
// those taken over QUIC because the same client produces different hellos on
// each.
const (
	transportTCP  = 't'
	transportQUIC = 'q'
)

// emptyListHash is what JA4 prints in place of a truncated SHA-256 when the
// list being hashed is empty. It is a literal run of zeros, not the hash of
// the empty string.
const emptyListHash = "000000000000"

// isGREASE reports whether v is one of the 16 GREASE values reserved by
// RFC 8701. Clients inject them into cipher, extension, version and group
// lists precisely so that middleboxes cannot assume a closed set, and they
// vary per connection — leaving them in would make the fingerprint different
// on every handshake, so every JA4 list drops them.
//
// The reserved values are 0x0a0a, 0x1a1a, ... 0xfafa: both bytes equal, and
// the low nibble of each is 0xa.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// withoutGREASE returns the values of in that are not GREASE, preserving
// order. It always allocates, so callers may sort the result in place.
func withoutGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// ja4 builds the JA4 fingerprint for ch. transport is transportTCP or
// transportQUIC.
func (ch *clientHello) ja4(transport byte) string {
	return ch.ja4WithExtensions(transport, ch.extensions)
}

// ja4Bind is deliberately NOT JA4: resuming a TLS/QUIC session introduces
// pre_shared_key (and sometimes early_data), and may change ClientHello
// padding. Those differences are connection state, not a different client
// stack. Keep the spec-exact JA4 for matching/blocking, but omit these
// unstable extensions when binding a long-lived clearance.
func (ch *clientHello) ja4Bind(transport byte) string {
	extensions := make([]uint16, 0, len(ch.extensions))
	for _, ext := range ch.extensions {
		if ext != extPreSharedKey && ext != extEarlyData && ext != extPadding {
			extensions = append(extensions, ext)
		}
	}
	return ch.ja4WithExtensions(transport, extensions)
}

func (ch *clientHello) ja4WithExtensions(transport byte, ext []uint16) string {
	ciphers := withoutGREASE(ch.cipherSuites)
	extensions := withoutGREASE(ext)

	var a strings.Builder
	a.WriteByte(transport)
	a.WriteString(tlsVersionCode(ch.version()))
	if ch.hasServerName {
		a.WriteByte('d') // hello carries a domain in SNI
	} else {
		a.WriteByte('i') // no SNI: the client dialed an IP
	}
	a.WriteString(twoDigitCount(len(ciphers)))
	a.WriteString(twoDigitCount(len(extensions)))
	a.WriteString(alpnCode(ch.firstALPN))

	return a.String() + "_" +
		truncatedHash(hexList(sortedCopy(ciphers))) + "_" +
		truncatedHash(ja4cList(extensions, withoutGREASE(ch.signatureAlgorithms)))
}

// ja4cList builds the string hashed into the third part of the fingerprint:
// the sorted extension list, then the signature algorithms in the order the
// client sent them, separated by an underscore.
//
// SNI and ALPN are dropped here even though they are counted in part "a".
// Both are already represented there (the "d"/"i" flag and the ALPN
// characters), and both vary with the site being visited rather than with the
// client, so including them would make one client produce a different
// fingerprint per destination.
//
// Signature algorithms are deliberately *not* sorted: their order is a
// property of the client's preference list and carries signal.
func ja4cList(extensions, signatureAlgorithms []uint16) string {
	filtered := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e == extServerName || e == extALPN {
			continue
		}
		filtered = append(filtered, e)
	}
	if len(filtered) == 0 {
		// Nothing to hash. Note this also covers the "no signature
		// algorithms" case: a hello that lists any signature algorithm
		// necessarily carries extension 0x000d, which survives the filter
		// above, so filtered cannot be empty while signatureAlgorithms is not.
		return ""
	}

	list := hexList(sortedCopy(filtered))
	if len(signatureAlgorithms) > 0 {
		list += "_" + hexList(signatureAlgorithms)
	}
	return list
}

// version returns the TLS version the hello is really offering.
//
// Since TLS 1.3 the legacy_version field is frozen at 0x0303 for backwards
// compatibility and the real list lives in the supported_versions extension,
// so that extension wins when present.
func (ch *clientHello) version() uint16 {
	var highest uint16
	for _, v := range ch.supportedVersions {
		if isGREASE(v) {
			continue
		}
		if v > highest {
			highest = v
		}
	}
	if highest != 0 {
		return highest
	}
	return ch.legacyVersion
}

// tlsVersionCode maps a wire version to its two-character JA4 code.
func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0x0100:
		return "s1"
	default:
		return "00"
	}
}

// twoDigitCount renders a list length as exactly two digits, saturating at 99
// so that an unusually long list cannot widen the fingerprint.
func twoDigitCount(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// alpnCode renders the two ALPN characters of part "a": the first and last
// character of the first protocol the client offered.
//
// A single-character protocol yields that character twice. A protocol whose
// first or last byte is not alphanumeric is rendered from its hex encoding
// instead, so that a non-printable value cannot corrupt the fingerprint's
// fixed-width layout.
func alpnCode(alpn string) string {
	if alpn == "" {
		return "00"
	}

	first, last := alpn[0], alpn[len(alpn)-1]
	if !isALPNAlphanumeric(first) || !isALPNAlphanumeric(last) {
		encoded := hex.EncodeToString([]byte(alpn))
		return string(encoded[0]) + string(encoded[len(encoded)-1])
	}
	return string(first) + string(last)
}

func isALPNAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// sortedCopy returns in sorted ascending. in is already a fresh slice from
// withoutGREASE, so it is sorted in place.
func sortedCopy(in []uint16) []uint16 {
	slices.Sort(in)
	return in
}

// hexList renders values as comma-separated four-digit lowercase hex, the
// form JA4 hashes.
func hexList(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// truncatedHash returns the first 12 hex characters of the SHA-256 of s, or
// the all-zero placeholder when there is nothing to hash.
func truncatedHash(s string) string {
	if s == "" {
		return emptyListHash
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
