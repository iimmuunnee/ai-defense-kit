package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pathForms lists the forms a temp path can take in output text: as is, with
// either slash style, and without the volume and leading separator (the form
// osv-scalibr uses in extraction errors).
func pathForms(p string) []string {
	fwd := filepath.ToSlash(p)
	forms := []string{p, fwd, strings.ReplaceAll(fwd, "/", `\`)}
	stripped := strings.TrimLeft(strings.TrimPrefix(fwd, filepath.VolumeName(p)), "/")
	if stripped != "" {
		forms = append(forms, stripped, strings.ReplaceAll(stripped, "/", `\`))
	}
	return forms
}

// TestScanBrokenLockfileLeaksNoPath runs the real OSV path (no fake scan)
// over a broken lockfile and checks no form of the temp root reaches the
// evidence or SARIF.
func TestScanBrokenLockfileLeaksNoPath(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "w4")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "package-lock.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(base, "db4")
	if err := os.MkdirAll(db, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "o4")
	_, _, se := runCLI(t, "scan", work, "--offline", "--osv-db", db, "--format", "json,sarif", "--out", out)
	ev, evb := readEvidence(t, out)
	sb, err := os.ReadFile(filepath.Join(out, "adk-report.sarif"))
	if err != nil {
		t.Fatalf("sarif: %v (stderr %s)", err, se)
	}
	deps := false
	for _, c := range ev.Checks {
		if c.Name != "deps" {
			continue
		}
		deps = true
		if c.Status != "failed" || !strings.Contains(c.Error, "could not extract") || !strings.Contains(c.Error, "package-lock.json") {
			t.Fatalf("deps check = %q / %q, want a failed extraction naming package-lock.json", c.Status, c.Error)
		}
	}
	if !deps {
		t.Fatalf("no deps check in evidence: %+v", ev.Checks)
	}
	for _, form := range pathForms(base) {
		for name, b := range map[string][]byte{"evidence": evb, "sarif": sb} {
			if strings.Contains(string(b), form) {
				t.Errorf("%s contains path form %q:\n%s", name, form, b)
			}
			// JSON escapes backslashes.
			esc, _ := json.Marshal(form)
			if strings.Contains(string(b), strings.Trim(string(esc), `"`)) {
				t.Errorf("%s contains escaped path form %q", name, form)
			}
		}
	}
}

// A scan folder name that also appears in file names and rule titles must not
// corrupt locations: PrivatePaths holds absolute forms only.
func TestScanRelativeTargetKeepsLocations(t *testing.T) {
	useFakeDeps(t)
	base := t.TempDir()
	api := filepath.Join(base, "api")
	if err := os.MkdirAll(filepath.Join(api, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	key := "K7Q2X9M4" + "T8W3Z6R1P5V0H2J9L7N4B8D3F6G1"
	for _, f := range []string{"api/keys.py", "api_client.js", "keys.py"} {
		if err := os.WriteFile(filepath.Join(api, f), []byte("API_KEY = \""+key+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	code, so, se := runCLI(t, "scan", "api", "--format", "sarif", "--offline")
	if code > 1 {
		t.Fatalf("exit %d: %s", code, se)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(so), &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) == 0 {
			t.Errorf("result without locations")
			continue
		}
		got[r.Locations[0].PhysicalLocation.ArtifactLocation.URI] = true
	}
	for _, want := range []string{"api/keys.py", "api_client.js", "keys.py"} {
		if !got[want] {
			t.Errorf("location %q missing, got %v", want, got)
		}
	}
	if strings.Contains(so, "<경로>") {
		t.Errorf("relative target was scrubbed:\n%s", so)
	}
}

// A report path that is refused before anything is written leaves the earlier
// files and the previous evidence file as they were: nothing changed, so the
// evidence still describes what is on disk.
func TestScanRefusedReportPathKeepsEvidence(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--format", "md,json", "--out", out); code != 0 {
		t.Fatalf("first run exit %d: %s", code, se)
	}
	ev := filepath.Join(out, "adk-evidence.json")
	if _, err := os.Stat(ev); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(out, "adk-report.json")
	if err := os.Remove(jsonPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(jsonPath, 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, _ := runCLI(t, "scan", sampleApp, "--format", "md,json", "--out", out)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if _, err := os.Stat(ev); err != nil {
		t.Errorf("evidence was removed although nothing was written: %v", err)
	}
}
