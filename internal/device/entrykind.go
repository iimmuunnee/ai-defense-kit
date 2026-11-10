package device

// entryKind is what a file system entry is to the search for text files.
type entryKind int

const (
	// kindOther: nothing to look at (a FIFO, a device, a junction Windows
	// keeps in every home folder for old programs).
	kindOther entryKind = iota
	kindFile
	kindDir
	// kindLink: a symbolic link or a junction. Not followed.
	kindLink
	// kindCloudOnly: the content (of a folder: the listing) is not on this
	// disk. Reading it would make a sync program download it.
	kindCloudOnly
	// kindUnknown: a reparse point of a kind this check does not know.
	// Whether reading it is harmless cannot be told.
	kindUnknown
)

// Windows file attributes and reparse tags, from winnt.h.
const (
	attrHidden             = 0x2
	attrSystem             = 0x4
	attrDirectory          = 0x10
	attrReparsePoint       = 0x400
	attrOffline            = 0x1000
	attrRecallOnOpen       = 0x40000
	attrRecallOnDataAccess = 0x400000

	// tagNameSurrogate is the bit of a tag that stands for another name:
	// symbolic links and junctions have it.
	tagNameSurrogate = 0x20000000
	tagSymlink       = 0xA000000C
	tagMountPoint    = 0xA0000003 // a junction
	// tagCloud is IO_REPARSE_TAG_CLOUD; the tags IO_REPARSE_TAG_CLOUD_1 to
	// _F differ from it only in the bits of tagCloudMask. OneDrive's Files
	// On-Demand marks every file and folder it keeps with one of them,
	// whether the content is on this disk or not.
	tagCloud     = 0x9000001A
	tagCloudMask = 0x0000F000
	tagDedup     = 0x80000013
	tagAFUnix    = 0x80000023
)

// windowsKind tells what a Windows entry is from its attributes and, when it
// is a reparse point, its tag. tagKnown is false when the tag could not be
// read.
//
// A link stands for another place and is not followed. A cloud placeholder
// is not a link: it is the file itself, read when its content is on this
// disk and passed by (and counted) when reading would download it.
func windowsKind(attrs, tag uint32, tagKnown bool) entryKind {
	if attrs&attrReparsePoint != 0 {
		switch {
		case !tagKnown:
			return kindUnknown
		case tag&tagNameSurrogate != 0:
			// The junctions Windows makes for old programs ("Application
			// Data", "My Documents", "My Music") are hidden system entries.
			// They are nothing the user put there.
			if tag == tagMountPoint && attrs&(attrHidden|attrSystem) == attrHidden|attrSystem {
				return kindOther
			}
			return kindLink
		case tag&^tagCloudMask == tagCloud, tag == tagDedup:
			// The file or folder itself: go by its attributes.
		case tag == tagAFUnix:
			return kindOther
		default:
			return kindUnknown
		}
	}
	// Reading a file with one of these downloads its content; listing a
	// folder with one fetches the listing.
	if attrs&(attrOffline|attrRecallOnOpen|attrRecallOnDataAccess) != 0 {
		return kindCloudOnly
	}
	if attrs&attrDirectory != 0 {
		return kindDir
	}
	return kindFile
}
