//go:build unix

package device

import (
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO swapped in after the Stat check must not make the open wait for a
// writer. If it blocks, the test binary's own timeout reports it.
func TestOpenReadFIFODoesNotWait(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	f, err := openRead(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Mode().IsRegular() {
		t.Fatalf("stat = %v, %v", st, err)
	}
}
