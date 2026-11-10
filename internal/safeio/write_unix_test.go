//go:build unix

package safeio

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func plantLink(t *testing.T) (link, outside string) {
	t.Helper()
	dir := t.TempDir()
	outside = filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(dir, "adk-report.md")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	return link, outside
}

func TestWriteFileRefusesSymlinkTarget(t *testing.T) {
	link, outside := plantLink(t)
	err := WriteFile(link, 0o644, func(w io.Writer) error { _, err := io.WriteString(w, "pwned"); return err })
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
}

func TestWriteFileRefusesFIFOTarget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	if err := WriteFile(p, 0o644, func(io.Writer) error { return nil }); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFileFollowsLinkedParentFolder(t *testing.T) {
	real := t.TempDir()
	parent := filepath.Join(t.TempDir(), "out")
	if err := os.Symlink(real, parent); err != nil {
		t.Skip(err)
	}
	if err := WriteFile(filepath.Join(parent, "a"), 0o644, func(w io.Writer) error { _, err := io.WriteString(w, "x"); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(real, "a")); err != nil {
		t.Fatal(err)
	}
}

func TestAppendFileRefusesSymlinkTarget(t *testing.T) {
	link, outside := plantLink(t)
	if err := AppendFile(link, 0o600, []byte("pwned\n")); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
}
