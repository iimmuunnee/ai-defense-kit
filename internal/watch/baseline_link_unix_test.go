//go:build unix

package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBaselineSaveRefusesSymlinkedPath(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "baseline.json")
	if err := os.Symlink(outside, p); err != nil {
		t.Skip(err)
	}
	if _, err := NewBaseline(time.Now(), nil).Save(p); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
}

func TestBaselineSaveKeepsOwnerOnlyMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	if _, err := NewBaseline(time.Now(), nil).Save(p); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, err %v", fi.Mode(), err)
	}
}
