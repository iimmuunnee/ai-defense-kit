package safeio

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileCleansTempWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	// After the check passes, a non-empty folder appears at the target, so
	// the rename cannot succeed.
	beforeRename = func(path string) {
		os.Mkdir(path, 0o755)
		os.WriteFile(filepath.Join(path, "x"), []byte("x"), 0o644)
	}
	t.Cleanup(func() { beforeRename = func(string) {} })
	err := WriteFile(p, 0o644, func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err })
	if err == nil {
		t.Fatal("expected an error")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "a.txt" {
		t.Fatalf("temp file left or folder missing: %v", ents)
	}
}

func TestWriteFileRefusesDanglingTarget(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), p); err != nil {
		t.Skip(err)
	}
	if err := WriteFile(p, 0o644, func(io.Writer) error { return nil }); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); err == nil {
		t.Fatal("dangling target was created")
	}
}

func TestCheckRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	if err := Check(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
	if err := Check(filepath.Join(dir, "missing")); err != nil {
		t.Fatal(err)
	}
}
