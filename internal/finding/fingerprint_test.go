package finding

import "testing"

// Two inputs that differ only in the value behind the mask are one input to
// the fingerprint: the value is not part of it.
func TestFingerprintIgnoresMaskedValue(t *testing.T) {
	const masked = "WALLET_PRIVATE_KEY=****"
	a := MakeMaskedFingerprint("WL-001", ".env", masked, 0)
	b := MakeMaskedFingerprint("WL-001", ".env", masked, 0)
	if a != b || len(a) != 16 {
		t.Fatalf("same masked evidence gave %q and %q", a, b)
	}
	if a == MakeMaskedFingerprint("WL-001", ".env", "OTHER_PRIVATE_KEY=****", 0) {
		t.Fatal("masked evidence must affect the fingerprint")
	}
	if a == MakeMaskedFingerprint("WL-001", "b/.env", masked, 0) || a == MakeMaskedFingerprint("WL-002", ".env", masked, 0) {
		t.Fatal("location and rule must affect the fingerprint")
	}
}

func TestFingerprintOccurrenceSeparatesRepeats(t *testing.T) {
	first := MakeMaskedFingerprint("WL-001", ".env", "K=****", 0)
	second := MakeMaskedFingerprint("WL-001", ".env", "K=****", 1)
	if first == second {
		t.Fatal("the same masked evidence twice must give two fingerprints")
	}
}

// The line number is no input, so moving a line down keeps its fingerprint.
func TestFingerprintStableWhenLinesMove(t *testing.T) {
	if MakeMaskedFingerprint("WL-001", ".env", "K=****", 0) != MakeMaskedFingerprint("WL-001", ".env", "K=****", 0) {
		t.Fatal("not stable")
	}
}

// A masked fingerprint never collides with a structural one made from the same text.
func TestMaskedFingerprintDiffersFromStructural(t *testing.T) {
	if MakeMaskedFingerprint("A", "b", "c", 0) == MakeFingerprint("A", "b", "c") {
		t.Fatal("masked and structural fingerprints must not share an input space")
	}
}
