//go:build unix

package watch

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// M5: a FIFO with no writer must be refused, not waited on. If it blocks, the
// test binary's own timeout reports it.
func TestPodsFIFOIsRefusedWithoutOpening(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pods.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	_, err := observePods(podsTarget(p, nil))
	if err == nil || !strings.Contains(err.Error(), "일반 파일") {
		t.Errorf("err = %v", err)
	}
}

// I5: a folder that really cannot be read, where no glob reaches.
func TestRepoUnreadableFolderOutsideTheGlobs(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read everything")
	}
	root := t.TempDir()
	put(t, root, "yarn.lock", "y")
	put(t, root, "locked/a.txt", "a")
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := observeRepo(t, map[string]any{"root": root}); err != nil {
		t.Errorf("err = %v", err)
	}
}
