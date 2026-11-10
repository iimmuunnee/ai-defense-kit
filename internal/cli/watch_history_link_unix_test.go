//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendJSONLRefusesSymlinkedHistory(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "history.jsonl")
	if err := os.Symlink(outside, p); err != nil {
		t.Skip(err)
	}
	if err := appendJSONL(p, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatalf("link target changed: %q", b)
	}
}
