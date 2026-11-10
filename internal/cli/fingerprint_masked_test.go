package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fingerprintsOf scans a repo whose env file holds one plain-word value and
// returns the fingerprints of the findings with the report's evidence.
func fingerprintsOf(t *testing.T, value string, lead string) map[string]string {
	t.Helper()
	useFakeDeps(t)
	app := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(app, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"dependencies":{"ethers":"6.0.0"}}`)
	write(".env", lead+"WALLET_PRIVATE_KEY="+value+"\n")
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "json", "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(out, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), value) {
		t.Fatalf("report holds the value %q", value)
	}
	var rep struct {
		Findings []struct {
			ID          string `json:"id"`
			Evidence    string `json:"evidence"`
			Fingerprint string `json:"fingerprint"`
		}
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range rep.Findings {
		if f.ID == "WL-001" {
			got[f.Evidence] = f.Fingerprint
		}
	}
	if len(got) == 0 {
		t.Fatalf("no WL-001 finding:\n%s", b)
	}
	return got
}

// A guess of the masked value cannot be confirmed by recomputing the
// fingerprint: two repos that differ only in the value share it, and moving
// the line does not change it.
func TestScanFingerprintNotDerivableFromValue(t *testing.T) {
	a := fingerprintsOf(t, "sunflower", "")
	b := fingerprintsOf(t, "umbrella", "")
	if len(a) != len(b) {
		t.Fatalf("finding sets differ: %v vs %v", a, b)
	}
	for ev, fp := range a {
		if b[ev] != fp {
			t.Errorf("evidence %q: fingerprint %q vs %q", ev, fp, b[ev])
		}
	}
	moved := fingerprintsOf(t, "sunflower", "# a comment\n\n")
	for ev, fp := range a {
		if moved[ev] != fp {
			t.Errorf("evidence %q: fingerprint moved with the line: %q vs %q", ev, fp, moved[ev])
		}
	}
}

// scanEnvFingerprints scans a repo with the given .env body and returns the
// WL-001 fingerprints in line order.
func scanEnvFingerprints(t *testing.T, body string) []string {
	t.Helper()
	useFakeDeps(t)
	app := t.TempDir()
	if err := os.WriteFile(filepath.Join(app, "package.json"), []byte(`{"dependencies":{"ethers":"6.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, ".env"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "json", "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(out, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			ID          string `json:"id"`
			Line        int    `json:"line"`
			Fingerprint string `json:"fingerprint"`
		}
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	var fps []string
	for _, f := range rep.Findings {
		if f.ID == "WL-001" {
			fps = append(fps, f.Fingerprint)
		}
	}
	return fps
}

// The same masked evidence on two lines of one file is two findings with two
// fingerprints, and an unrelated line inserted above changes neither.
func TestScanRepeatedEvidenceGetsOccurrenceFingerprints(t *testing.T) {
	two := "WALLET_PRIVATE_KEY=" + "sun" + "flower\nWALLET_PRIVATE_KEY=" + "um" + "brella\n"
	base := scanEnvFingerprints(t, two)
	if len(base) != 2 || base[0] == base[1] {
		t.Fatalf("fingerprints = %v, want two distinct", base)
	}
	moved := scanEnvFingerprints(t, "# unrelated\nNODE_ENV=dev\n"+two)
	if len(moved) != 2 || moved[0] != base[0] || moved[1] != base[1] {
		t.Errorf("fingerprints moved with an inserted line: %v vs %v", moved, base)
	}
}
