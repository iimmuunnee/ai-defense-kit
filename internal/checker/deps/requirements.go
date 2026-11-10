package deps

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxRequirementsSize caps how much of a requirements file is read.
const maxRequirementsSize = 1 << 20

// skipDirs are not walked when collecting requirements files (same set as the
// rules engine).
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".next": true, "dist": true,
	"build": true, "vendor": true, ".venv": true, "__pycache__": true,
}

var (
	errTooLarge   = errors.New("requirements 파일이 1MB를 넘습니다")
	errNotRegular = errors.New("일반 파일이 아닙니다")
)

// Requirement is one package line of a requirements file.
type Requirement struct {
	Name    string // PEP 503 normalized
	Exact   bool   // pinned with ==X (no wildcard) or ===X
	Version string // the pinned version when Exact
	Line    int    // 1-based line number where the entry starts
	Raw     string
}

var (
	reNameLine  = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$`)
	reSepRun    = regexp.MustCompile(`[-_.]+`)
	reExactSpec = regexp.MustCompile(`^(===|==)\s*(\S+)$`)
)

// normalizeName applies PEP 503 normalization.
func normalizeName(s string) string {
	return reSepRun.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
}

// ParseRequirements extracts package requirements. Comments, blank lines,
// option lines (-r, -c, -e, ...), URL and path lines and "name @ url" lines are
// left out. Environment markers and per-line --hash options are ignored.
// "-r other.txt" is not followed here; loadRequirementsTree follows it.
func ParseRequirements(content string) []Requirement {
	reqs, _ := parseRequirementsFile(content)
	return reqs
}

// parseRequirementsFile also returns the paths named by -r / --requirement.
func parseRequirementsFile(content string) (out []Requirement, includes []string) {
	content = strings.TrimPrefix(content, "\ufeff")
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		start := i + 1
		line := lines[i]
		// join backslash continuations (typical with --hash lines), but a
		// comment line ending in "\" does not continue
		for !strings.HasPrefix(strings.TrimSpace(line), "#") &&
			strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " " + lines[i+1]
			i++
		}
		raw := strings.TrimSpace(line)
		if inc, ok := includePath(raw); ok {
			includes = append(includes, inc)
			continue
		}
		if r, ok := parseRequirementLine(raw); ok {
			r.Line = start
			r.Raw = raw
			out = append(out, r)
		}
	}
	return out, includes
}

var (
	reInlineComment = regexp.MustCompile(`[ \t]#`)
	reOptionStart   = regexp.MustCompile(`[ \t]--`)
	reInclude       = regexp.MustCompile(`^(?:-r|--requirement)(?:[ \t]+|=)?(\S.*)$`)
)

// includePath returns the file named by a "-r file" line.
func includePath(s string) (string, bool) {
	if strings.HasPrefix(s, "#") {
		return "", false
	}
	if loc := reInlineComment.FindStringIndex(s); loc != nil {
		s = s[:loc[0]]
	}
	m := reInclude.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	p := strings.TrimSpace(m[1])
	if p == "" || strings.Contains(p, "://") {
		return "", false
	}
	return p, true
}

func parseRequirementLine(s string) (Requirement, bool) {
	if strings.HasPrefix(s, "#") {
		return Requirement{}, false
	}
	if loc := reInlineComment.FindStringIndex(s); loc != nil { // needs leading whitespace
		s = s[:loc[0]]
	}
	if j := strings.Index(s, ";"); j >= 0 { // environment marker
		s = s[:j]
	}
	if loc := reOptionStart.FindStringIndex(s); loc != nil { // per-requirement options
		s = s[:loc[0]]
	}
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") || strings.Contains(s, "://") ||
		strings.ContainsAny(s, `/\`) || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return Requirement{}, false
	}
	m := reNameLine.FindStringSubmatch(s)
	if m == nil {
		return Requirement{}, false
	}
	name, rest := m[1], strings.TrimSpace(m[2])
	if strings.HasPrefix(rest, "@") { // direct reference
		return Requirement{}, false
	}
	if rest == "" && isArchiveName(name) {
		return Requirement{}, false
	}
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")"))
	r := Requirement{Name: normalizeName(name)}
	if rest != "" && !strings.Contains(rest, ",") {
		if sm := reExactSpec.FindStringSubmatch(rest); sm != nil {
			r.Exact = sm[1] == "===" || !strings.Contains(sm[2], "*")
			if r.Exact {
				r.Version = sm[2]
			}
		}
	}
	return r, true
}

func isArchiveName(s string) bool {
	l := strings.ToLower(s)
	for _, ext := range []string{".whl", ".zip", ".tar.gz", ".tgz", ".egg"} {
		if strings.HasSuffix(l, ext) {
			return true
		}
	}
	return false
}

// isRequirementsFile uses the same condition as osv-scalibr's requirements
// extractor: extension ".txt" and "requirements" anywhere in the base name.
func isRequirementsFile(name string) bool {
	return filepath.Ext(name) == ".txt" && strings.Contains(name, "requirements")
}

// maxIncludeDepth bounds how many levels of "-r" are followed.
const maxIncludeDepth = 5

// readRequirementsFile reads one regular (non-symlink) file under the size cap.
func readRequirementsFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRequirementsSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxRequirementsSize {
		return "", errTooLarge
	}
	return string(b), nil
}

// loadRequirementsTree parses path and the files it includes with -r. An
// include is resolved relative to the including file, must stay inside root,
// is followed up to maxIncludeDepth levels and only once (cycle-safe). Files
// that cannot be read are returned in unreadable.
func loadRequirementsTree(root, path string) (reqs []Requirement, unreadable []string) {
	visited := map[string]bool{}
	var visit func(p string, depth int)
	visit = func(p string, depth int) {
		p = filepath.Clean(p)
		if visited[p] {
			return
		}
		visited[p] = true
		if rel, err := filepath.Rel(root, p); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			unreadable = append(unreadable, p)
			return
		}
		content, err := readRequirementsFile(p)
		if err != nil {
			unreadable = append(unreadable, p)
			return
		}
		rs, incs := parseRequirementsFile(content)
		reqs = append(reqs, rs...)
		for _, inc := range incs {
			ip := inc
			if !filepath.IsAbs(ip) {
				ip = filepath.Join(filepath.Dir(p), ip)
			}
			if depth >= maxIncludeDepth {
				unreadable = append(unreadable, filepath.Clean(ip))
				continue
			}
			visit(ip, depth+1)
		}
	}
	visit(path, 0)
	return reqs, unreadable
}

// unpinnedNames walks root for requirements files (isRequirementsFile; symlinks
// are skipped) and returns the sorted unique normalized names that are not pinned exactly,
// including those in files they include, plus the files that could not be read.
func unpinnedNames(root string) (names []string, unreadable []string) {
	set := map[string]bool{}
	bad := map[string]bool{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isRequirementsFile(d.Name()) {
			return nil
		}
		reqs, bads := loadRequirementsTree(root, p)
		for _, b := range bads {
			if !bad[b] {
				bad[b] = true
				unreadable = append(unreadable, b)
			}
		}
		for _, r := range reqs {
			if !r.Exact {
				set[r.Name] = true
			}
		}
		return nil
	})
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, unreadable
}
