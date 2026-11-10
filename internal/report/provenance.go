package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Values of the git-dirty field in evidence output.
const (
	DirtyYes     = "yes"
	DirtyNo      = "no"
	DirtyUnknown = "unknown"
)

// Where a data set came from.
const (
	OriginBuiltin = "builtin"
	OriginCustom  = "custom"
)

// DataSet identifies one rule/mapping data set by content.
type DataSet struct {
	Origin string `json:"origin"`
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}

// MappingSource is the source version and review state of one mapping item.
type MappingSource struct {
	ID            string `json:"id"`
	SourceVersion string `json:"source_version"`
	ReviewStatus  string `json:"review_status"`
}

// MappingData is the mapping data set plus its per-item sources.
type MappingData struct {
	DataSet
	Items []MappingSource `json:"items"`
}

// DataVersions records which rule and mapping data a scan used.
type DataVersions struct {
	Rules    *DataSet    `json:"rules"` // nil for adk assets
	Mappings MappingData `json:"mappings"`
}

// Component is a scanning library compiled into the binary.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HashTree returns the hex SHA-256 over every file under dir, in path order.
// Each file contributes "<path length>\x00<path><content length>\x00<content>"
// so that different splits of the same bytes hash differently. A missing dir
// hashes like empty input.
func HashTree(fsys fs.FS, dir string) (string, error) {
	var paths []string
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil && !isNotExist(err) {
		return "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return "", err
		}
		h.Write([]byte(strconv.Itoa(len(p))))
		h.Write([]byte{0})
		h.Write([]byte(p))
		h.Write([]byte(strconv.Itoa(len(data))))
		h.Write([]byte{0})
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// Components lists the scanner libraries found in info. It never returns nil.
func Components(info *debug.BuildInfo) []Component {
	out := []Component{}
	if info == nil {
		return out
	}
	names := map[string]string{
		"github.com/google/osv-scanner/v2":   "osv-scanner",
		"github.com/zricethezav/gitleaks/v8": "gitleaks",
	}
	for _, d := range info.Deps {
		if d == nil {
			continue
		}
		if n, ok := names[d.Path]; ok {
			out = append(out, Component{Name: n, Version: d.Version})
		}
	}
	return out
}

const noName = "(이름 없음)"

// TargetName is the last element of root, without any parent path.
func TargetName(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return noName
	}
	base := strings.Trim(filepath.Base(root), `/\`)
	if base == "" || base == "." {
		if vol := filepath.VolumeName(root); vol != "" {
			return vol
		}
		return noName
	}
	return base
}

// Scrub removes absolute paths from s: scanRoot becomes "." and each of
// others becomes "<경로>". Both slash styles are replaced, longest path first.
// Empty paths and bare volume roots ("D:\", "/") are ignored.
//
// Every path is replaced only on path boundaries: it must not follow a letter,
// digit, '_', '-' or '.', and must not be followed by one, or by a '.' that
// starts another name part ("app.bak"). Hangul is always a boundary. A
// sentence-ending '.' after a path is not part of it. So a root like "/app"
// cannot erase the word "app" or change "src/app/page.tsx".
//
// Some libraries (osv-scalibr) print a path without its drive and leading
// separator, such as "Users/me/proj/package-lock.json". That stripped form is
// replaced too, but only when it has at least two segments.
func Scrub(s, scanRoot string, others []string) string {
	type rep struct{ from, to string }
	var reps []rep
	add := func(p, to string) {
		p = strings.TrimRight(p, `/\`)
		if p == "" || isBareVolume(p) {
			return
		}
		fwd := strings.ReplaceAll(p, `\`, "/")
		bwd := strings.ReplaceAll(p, "/", `\`)
		reps = append(reps, rep{fwd, to})
		if bwd != fwd {
			reps = append(reps, rep{bwd, to})
		}
		stripped := fwd
		if len(stripped) >= 2 && stripped[1] == ':' {
			stripped = stripped[2:]
		}
		stripped = strings.TrimLeft(stripped, "/")
		segments := 0
		for _, seg := range strings.Split(stripped, "/") {
			if seg != "" {
				segments++
			}
		}
		if segments < 2 {
			return
		}
		reps = append(reps, rep{stripped, to})
		if back := strings.ReplaceAll(stripped, "/", `\`); back != stripped {
			reps = append(reps, rep{back, to})
		}
	}
	add(scanRoot, ".")
	for _, o := range others {
		add(o, "<경로>")
	}
	sort.SliceStable(reps, func(i, j int) bool { return len(reps[i].from) > len(reps[j].from) })
	for _, r := range reps {
		s = replaceOnBoundary(s, r.from, r.to)
	}
	return s
}

// isBareVolume reports whether p is only a drive letter such as "D:".
func isBareVolume(p string) bool {
	return len(p) == 2 && p[1] == ':' && unicode.IsLetter(rune(p[0]))
}

// isNameRune reports whether r continues a file name. Hangul does not count:
// adk's messages are Korean, so a particle or word can sit right next to a path
// ("D:\proj에서"), and leaving the path visible is worse than splitting a
// Korean folder name.
func isNameRune(r rune) bool {
	if unicode.Is(unicode.Hangul, r) {
		return false
	}
	return r == '_' || r == '-' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// replaceOnBoundary replaces from with to where from is not glued to a name
// character on either side. A separator before it is fine: that is the
// leading separator the stripped form lacks. Both sides are checked against
// the original s, so a rejected match never hides the text before the next one.
func replaceOnBoundary(s, from, to string) string {
	var b strings.Builder
	last, pos := 0, 0
	for pos <= len(s) {
		j := strings.Index(s[pos:], from)
		if j < 0 {
			break
		}
		i := pos + j
		end := i + len(from)
		okBefore, okAfter := true, true
		if i > 0 {
			r, _ := utf8.DecodeLastRuneInString(s[:i])
			okBefore = !isNameRune(r)
		}
		if end < len(s) {
			r, size := utf8.DecodeRuneInString(s[end:])
			if r == '.' {
				// A dot is the end of a sentence unless a name part follows it.
				// Another dot is not a name part: "proj..." and "proj..\x".
				if end+size < len(s) {
					next, _ := utf8.DecodeRuneInString(s[end+size:])
					okAfter = next == '.' || !isNameRune(next)
				}
			} else {
				okAfter = !isNameRune(r)
			}
		}
		if okBefore && okAfter {
			b.WriteString(s[last:i])
			b.WriteString(to)
			last, pos = end, end
		} else {
			pos = i + 1
		}
	}
	b.WriteString(s[last:])
	return b.String()
}

// canonicalFindings returns a sorted copy of fs: the usual finding.Sort order,
// with remaining ties ordered by ID, Kind and Fingerprint. Without the
// tie-break, findings that tie on every sort key keep the order they arrived
// in, which changes SARIF rule order and occurrence numbers between runs.
func canonicalFindings(fs []finding.Finding) []finding.Finding {
	out := append([]finding.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Fingerprint < b.Fingerprint
	})
	finding.Sort(out)
	return out
}
