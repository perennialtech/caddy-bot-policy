package botpolicy

import "testing"

// TestFingerprintMatchesInternalPath pins the exported entry point to the same
// value the listener wrapper stores, so a catalogue built with ja4probe stays
// comparable to the fingerprints seen in production.
func TestFingerprintMatchesInternalPath(t *testing.T) {
	b := fullHello()

	ch, err := parseClientHello(b.body())
	if err != nil {
		t.Fatalf("parseClientHello: %v", err)
	}
	want := ch.ja4(transportTCP)

	got, err := Fingerprint(b.records(0))
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got != want {
		t.Errorf("Fingerprint = %q, listener path = %q", got, want)
	}
}

// TestFingerprintReassemblesRecords covers a hello split across several TLS
// records, which is how large hellos (post-quantum key shares) arrive.
func TestFingerprintReassemblesRecords(t *testing.T) {
	b := fullHello()

	whole, err := Fingerprint(b.records(0))
	if err != nil {
		t.Fatalf("Fingerprint whole: %v", err)
	}
	split, err := Fingerprint(b.records(16))
	if err != nil {
		t.Fatalf("Fingerprint split: %v", err)
	}
	if whole != split {
		t.Errorf("fragmentation changed the fingerprint: %q vs %q", whole, split)
	}
}

// TestFingerprintRejectsNonHandshake makes sure plain HTTP on the same port
// fails instead of producing a fingerprint from garbage.
func TestFingerprintRejectsNonHandshake(t *testing.T) {
	if _, err := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err == nil {
		t.Fatal("expected an error for non-TLS bytes")
	}
}

// TestFingerprintErrorsWhileIncomplete is what lets a streaming caller retry:
// a short read has to look like an error, not like an empty fingerprint.
func TestFingerprintErrorsWhileIncomplete(t *testing.T) {
	records := fullHello().records(0)
	for _, n := range []int{1, 5, len(records) - 1} {
		if _, err := Fingerprint(records[:n]); err == nil {
			t.Errorf("expected an error for a %d-byte prefix", n)
		}
	}
}
