package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleBaseline() Baseline {
	return Baseline{
		Version:   1,
		CreatedAt: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC),
		Entries:   map[string]Observation{"a": {"x": "1", "y": "2"}},
	}
}

func TestLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.json")
	sum, err := sampleBaseline().Save(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 64 {
		t.Fatalf("sha256 hex expected, got %q", sum)
	}

	got, err := LoadBaseline(path, "")
	if err != nil || got.Entries["a"]["y"] != "2" || got.Version != 1 {
		t.Fatalf("load: %+v %v", got, err)
	}
	if _, err := LoadBaseline(path, sum); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	if _, err := LoadBaseline(path, strings.ToUpper(sum)); err != nil {
		t.Fatalf("pin should be case-insensitive: %v", err)
	}
	wrong := strings.Repeat("0", 64)
	if _, err := LoadBaseline(path, wrong); err == nil {
		t.Fatal("expected pin mismatch error")
	}
	if _, err := LoadBaseline(filepath.Join(dir, "missing.json"), ""); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadBaselineRejects(t *testing.T) {
	cases := map[string]string{
		"corrupt":         "{not json",
		"wrong version":   `{"version":2,"created_at":"2026-11-06T00:00:00Z","entries":{}}`,
		"missing version": `{"entries":{}}`,
		"missing entries": `{"version":1,"created_at":"2026-11-06T00:00:00Z"}`,
		"null entries":    `{"version":1,"entries":null}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "b.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadBaseline(p, ""); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSaveOverwritesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.json")
	b := sampleBaseline()
	if _, err := b.Save(path); err != nil {
		t.Fatal(err)
	}
	b.Entries["a"]["x"] = "changed"
	sum, err := b.Save(path)
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := LoadBaseline(path, sum)
	if err != nil || got.Entries["a"]["x"] != "changed" {
		t.Fatalf("after overwrite: %+v %v", got, err)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 {
		t.Fatalf("temp file left behind: %v", es)
	}

	// Failure path: the destination is a non-empty directory, so rename fails.
	bad := filepath.Join(dir, "d")
	if err := os.MkdirAll(filepath.Join(bad, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Save(bad); err == nil {
		t.Fatal("expected error")
	}
	es, _ = os.ReadDir(dir)
	if len(es) != 2 {
		t.Fatalf("temp file left behind after failure: %v", es)
	}
}

func TestNewBaselineAndHashes(t *testing.T) {
	now := time.Date(2026, 11, 6, 1, 2, 3, 0, time.UTC)
	b := NewBaseline(now, map[string]Observation{"a": {"x": "1"}})
	if b.Version != baselineVersion || !b.CreatedAt.Equal(now) || b.Entries["a"]["x"] != "1" {
		t.Fatalf("baseline = %+v", b)
	}
	path := filepath.Join(t.TempDir(), "b.json")
	want, err := b.SHA256()
	if err != nil || want == "" {
		t.Fatalf("SHA256: %q %v", want, err)
	}
	saved, err := b.Save(path)
	if err != nil || saved != want {
		t.Fatalf("Save = %q %v, want %q", saved, err, want)
	}
	onDisk, err := FileSHA256(path)
	if err != nil || onDisk != want {
		t.Fatalf("FileSHA256 = %q %v, want %q", onDisk, err, want)
	}
	if _, err := LoadBaseline(path, want); err != nil {
		t.Fatalf("a baseline made by NewBaseline must load: %v", err)
	}
	if _, err := FileSHA256(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("missing file must be an error")
	}
}
