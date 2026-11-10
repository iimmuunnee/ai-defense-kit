package device

import "testing"

// What Windows says about an entry, and what the search does with it. No
// OneDrive placeholder was at hand to try this on: the attribute and tag
// values are those of winnt.h, and this table is the whole check.
func TestWindowsKind(t *testing.T) {
	const (
		dir     = attrDirectory
		reparse = attrReparsePoint
		archive = 0x20
		pinned  = 0x80000
	)
	for _, c := range []struct {
		name     string
		attrs    uint32
		tag      uint32
		tagKnown bool
		want     entryKind
	}{
		{"plain file", archive, 0, false, kindFile},
		{"plain folder", dir, 0, false, kindDir},
		{"symbolic link to a file", archive | reparse, tagSymlink, true, kindLink},
		{"symbolic link to a folder", dir | reparse, tagSymlink, true, kindLink},
		{"junction", dir | reparse, tagMountPoint, true, kindLink},
		{"junction Windows keeps for old programs", dir | reparse | attrHidden | attrSystem, tagMountPoint, true, kindOther},
		{"hidden system symbolic link", dir | reparse | attrHidden | attrSystem, tagSymlink, true, kindLink},
		{"OneDrive file on this disk", archive | reparse, tagCloud | 0x6000, true, kindFile},
		{"OneDrive file on this disk, always kept", archive | reparse | pinned, tagCloud | 0x7000, true, kindFile},
		{"OneDrive file online only", archive | reparse | attrRecallOnDataAccess | attrOffline, tagCloud | 0x6000, true, kindCloudOnly},
		{"OneDrive file online only, data access", archive | reparse | attrRecallOnDataAccess, tagCloud, true, kindCloudOnly},
		{"cloud file recalled on open", archive | reparse | attrRecallOnOpen, tagCloud | 0xF000, true, kindCloudOnly},
		{"OneDrive folder", dir | reparse, tagCloud | 0x2000, true, kindDir},
		{"OneDrive folder not listed yet", dir | reparse | attrRecallOnOpen, tagCloud | 0x2000, true, kindCloudOnly},
		{"cloud folder whose listing is fetched on reading", dir | reparse | attrRecallOnDataAccess, tagCloud | 0x2000, true, kindCloudOnly},
		{"offline folder", dir | attrOffline, 0, false, kindCloudOnly},
		{"online-only file shown without its reparse point", archive | attrRecallOnDataAccess, 0, false, kindCloudOnly},
		{"offline file", archive | attrOffline, 0, false, kindCloudOnly},
		{"deduplicated file", archive | reparse, tagDedup, true, kindFile},
		{"socket", archive | reparse, tagAFUnix, true, kindOther},
		{"app execution alias", archive | reparse, 0x8000001B, true, kindUnknown},
		{"reparse point of another kind", dir | reparse, 0x80000017, true, kindUnknown},
		{"reparse point whose tag could not be read", archive | reparse, 0, false, kindUnknown},
		{"a tag near the cloud tags", archive | reparse, 0x9000001B, true, kindUnknown},
	} {
		if got := windowsKind(c.attrs, c.tag, c.tagKnown); got != c.want {
			t.Errorf("%s: kind %d, want %d", c.name, got, c.want)
		}
	}
}
