//go:build windows

package device

import (
	"path/filepath"
	"testing"
)

// Windows tells where the Desktop, Documents and Downloads folders are.
func TestKnownFoldersAreAbsolutePaths(t *testing.T) {
	got := KnownFolders()
	if len(got) == 0 {
		t.Skip("this account has no known folders")
	}
	for i, p := range got {
		if !filepath.IsAbs(p) {
			t.Errorf("known folder %d is not an absolute path", i)
		}
	}
}
