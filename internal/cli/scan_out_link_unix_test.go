//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanOutRefusesSymlinkedReport(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(out, "adk-report.md")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	code, _, stderr := runCLI(t, "scan", sampleApp, "--format", "md", "--out", out)
	if code != 2 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, link) {
		t.Fatalf("error does not name the path: %s", stderr)
	}
	if strings.Contains(stderr, outside) {
		t.Fatalf("error leaks the link target: %s", stderr)
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
}

func TestScanOutRefusesSymlinkedEvidence(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(out, "adk-evidence.json")); err != nil {
		t.Skip(err)
	}
	code, _, stderr := runCLI(t, "scan", sampleApp, "--format", "md", "--out", out)
	if code != 2 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
}

func TestScanOutRefusedPathLeavesEarlierFilesAndEvidence(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim.txt")
	for p, s := range map[string]string{
		outside:                                 "keep",
		filepath.Join(out, "adk-report.md"):     "old report",
		filepath.Join(out, "adk-evidence.json"): "old evidence",
	} {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(out, "adk-report.json")); err != nil {
		t.Skip(err)
	}
	code, _, stderr := runCLI(t, "scan", sampleApp, "--format", "md,json", "--out", out)
	if code != 2 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for p, want := range map[string]string{
		filepath.Join(out, "adk-report.md"):     "old report",
		filepath.Join(out, "adk-evidence.json"): "old evidence",
		outside:                                 "keep",
	} {
		if b, _ := os.ReadFile(p); string(b) != want {
			t.Fatalf("%s changed: %q", p, b)
		}
	}
	if ents, _ := os.ReadDir(out); len(ents) != 3 {
		t.Fatalf("unexpected files: %v", ents)
	}
}
