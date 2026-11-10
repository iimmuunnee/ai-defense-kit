//go:build !windows && !darwin

package device

import "io/fs"

// kindOf tells what the entry at path is. fi is its Lstat.
func kindOf(_ string, fi fs.FileInfo) entryKind {
	switch m := fi.Mode(); {
	case m&fs.ModeSymlink != 0:
		return kindLink
	case m.IsDir():
		return kindDir
	case m.IsRegular():
		return kindFile
	}
	return kindOther
}

// linkOf: the entry is a symbolic link.
func linkOf(_ string, fi fs.FileInfo) bool { return fi.Mode()&fs.ModeSymlink != 0 }

// needsFetch: no file here is known to be fetched on reading.
func needsFetch(fs.FileInfo) bool { return false }

// linksToDir: not known without following the link.
func linksToDir(fs.FileInfo) bool { return false }

// KnownFolders: the folders are where the home folder has them.
func KnownFolders() []string { return nil }
