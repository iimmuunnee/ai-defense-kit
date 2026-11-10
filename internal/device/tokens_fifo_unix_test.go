//go:build unix

package device

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A FIFO named by KUBECONFIG must be refused, not waited on. If it blocks, the
// test binary's own timeout reports it.
func TestFIFOIsRefusedWithoutOpening(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	fs, unread := CheckTokens(t.TempDir(), envOf(map[string]string{"KUBECONFIG": p}))
	if len(fs) != 0 || len(unread) != 1 || !strings.Contains(unread[0], "일반 파일") {
		t.Fatalf("findings=%v unreadable=%v", evidences(fs), unread)
	}
}
