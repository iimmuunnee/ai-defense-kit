//go:build unix

package safeio

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func put(w io.Writer) error { _, err := io.WriteString(w, "x"); return err }

func TestWriteFileKeepsModeOfExistingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, 0o644, put); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestWriteFileNewFileFollowsUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := WriteFile(p, 0o644, put); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("group/world access: %v", fi.Mode().Perm())
	}
}

func TestWriteFileNewFileUsesGivenPerm(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := WriteFile(p, 0o600, put); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestAppendFileOnFIFODoesNotHang(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := openAppend(p, 0o600); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("open hung on a FIFO")
	}
	if err := AppendFile(p, 0o600, []byte("x")); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("got %v", err)
	}
}
