package safeio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileReplacesRegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, 0o644, func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("got %q", b)
	}
}

func TestWriteFileCreatesMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := WriteFile(p, 0o600, func(w io.Writer) error { _, err := io.WriteString(w, "x"); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Fatalf("got %q", b)
	}
}

func TestWriteFileRefusesFolderTarget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	err := WriteFile(p, 0o644, func(io.Writer) error { return nil })
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFileLeavesNoTempOnError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	boom := fmt.Errorf("boom")
	err := WriteFile(p, 0o644, func(w io.Writer) error { io.WriteString(w, "partial"); return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("existing file changed: %q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp file left: %v", ents)
	}
}

func TestAppendFileAppendsAndCreates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.jsonl")
	for _, s := range []string{"a\n", "b\n"} {
		if err := AppendFile(p, 0o600, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != "a\nb\n" {
		t.Fatalf("got %q", b)
	}
}
