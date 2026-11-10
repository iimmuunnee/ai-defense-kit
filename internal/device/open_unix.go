//go:build unix

package device

import (
	"os"
	"syscall"
)

// openRead opens path for reading without waiting: a FIFO put in place after
// the caller's Stat would otherwise block the open until a writer comes. The
// caller checks the opened file is regular.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
