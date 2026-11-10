//go:build windows

package device

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// kindOf tells what the entry at path is. fi is its Lstat (or the Info of
// its directory entry).
func kindOf(path string, fi fs.FileInfo) entryKind {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return kindUnknown
	}
	if d.FileAttributes&attrReparsePoint == 0 {
		return windowsKind(d.FileAttributes, 0, false)
	}
	tag, listed, ok := reparseTag(path)
	// Some attributes ("recall on open") show only in a folder listing.
	return windowsKind(d.FileAttributes|listed, tag, ok)
}

// linkOf: the entry is a symbolic link or a junction, whatever else is set
// on it.
func linkOf(path string, fi fs.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok || d.FileAttributes&attrReparsePoint == 0 {
		return false
	}
	tag, _, ok := reparseTag(path)
	return ok && tag&tagNameSurrogate != 0
}

// needsFetch: reading the opened file would download it.
func needsFetch(fi fs.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&(attrOffline|attrRecallOnOpen|attrRecallOnDataAccess) != 0
}

// linksToDir: the link stands for a folder.
func linksToDir(fi fs.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&attrDirectory != 0
}

// reparseTag reads the reparse tag of the entry at path, and its attributes
// as a listing shows them, from its directory entry: the entry is not
// opened.
func reparseTag(path string) (tag, attrs uint32, ok bool) {
	p, err := syscall.UTF16PtrFromString(longPath(path))
	if err != nil {
		return 0, 0, false
	}
	var fd syscall.Win32finddata
	h, err := syscall.FindFirstFile(p, &fd)
	if err != nil {
		return 0, 0, false
	}
	syscall.FindClose(h)
	if fd.FileAttributes&attrReparsePoint == 0 {
		return 0, 0, false
	}
	// For a reparse point, dwReserved0 of WIN32_FIND_DATA is its tag.
	return fd.Reserved0, fd.FileAttributes, true
}

// longPath lets a path longer than MAX_PATH through to the Windows call.
func longPath(path string) string {
	const (
		verbatim = `\\?\`
		network  = `\\`
	)
	path = filepath.Clean(path)
	switch {
	case len(path) < 248 || strings.HasPrefix(path, verbatim) || !filepath.IsAbs(path):
		return path
	case strings.HasPrefix(path, network):
		return verbatim + `UNC\` + path[len(network):]
	}
	return verbatim + path
}

var (
	shell32                  = syscall.NewLazyDLL("shell32.dll")
	ole32                    = syscall.NewLazyDLL("ole32.dll")
	procSHGetKnownFolderPath = shell32.NewProc("SHGetKnownFolderPath")
	procCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")
)

// KnownFolders asks Windows where the Desktop, Documents and Downloads
// folders are: they can be moved out of the home folder (to another drive,
// or into OneDrive).
func KnownFolders() []string {
	var out []string
	for _, id := range []syscall.GUID{
		{Data1: 0xB4BFCC3A, Data2: 0xDB2C, Data3: 0x424C, Data4: [8]byte{0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}}, // FOLDERID_Desktop
		{Data1: 0xFDD39AD0, Data2: 0x238F, Data3: 0x46AF, Data4: [8]byte{0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}}, // FOLDERID_Documents
		{Data1: 0x374DE290, Data2: 0x123F, Data3: 0x4565, Data4: [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}}, // FOLDERID_Downloads
	} {
		var p *uint16
		r, _, _ := procSHGetKnownFolderPath.Call(uintptr(unsafe.Pointer(&id)), 0, 0, uintptr(unsafe.Pointer(&p)))
		if r == 0 && p != nil {
			// Up to the terminating zero, and no further.
			var units []uint16
			for q := p; *q != 0 && len(units) < 1<<15; q = (*uint16)(unsafe.Add(unsafe.Pointer(q), 2)) {
				units = append(units, *q)
			}
			out = append(out, syscall.UTF16ToString(units))
		}
		if p != nil {
			procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
		}
	}
	return out
}
