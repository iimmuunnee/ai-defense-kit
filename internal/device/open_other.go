//go:build !unix

package device

import "os"

// openRead opens path for reading. Outside Unix there are no FIFOs in the
// file system to wait on.
func openRead(path string) (*os.File, error) {
	return os.Open(path)
}
