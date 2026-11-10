//go:build darwin

package device

import (
	"io/fs"
	"syscall"
)

// sfDataless marks a file whose content is not on this disk (iCloud Drive and
// File Provider folders): reading it downloads it. SF_DATALESS in xnu's
// bsd/sys/stat.h. Not run on a real Mac.
const sfDataless = 0x40000000

// kindOf tells what the entry at path is. fi is its Lstat.
func kindOf(_ string, fi fs.FileInfo) entryKind {
	st, _ := fi.Sys().(*syscall.Stat_t)
	switch m := fi.Mode(); {
	case m&fs.ModeSymlink != 0:
		return kindLink
	case st != nil && st.Flags&sfDataless != 0 && (m.IsDir() || m.IsRegular()):
		return kindCloudOnly
	case m.IsDir():
		return kindDir
	case m.IsRegular():
		return kindFile
	}
	return kindOther
}

// linkOf: the entry is a symbolic link.
func linkOf(_ string, fi fs.FileInfo) bool { return fi.Mode()&fs.ModeSymlink != 0 }

// needsFetch: reading the opened file would download it.
func needsFetch(fi fs.FileInfo) bool {
	st, _ := fi.Sys().(*syscall.Stat_t)
	return st != nil && st.Flags&sfDataless != 0
}

// linksToDir: not known without following the link.
func linksToDir(fs.FileInfo) bool { return false }

// KnownFolders: the folders are where the home folder has them.
func KnownFolders() []string { return nil }
