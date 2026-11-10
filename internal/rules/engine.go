package rules

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	maxFileSize = 1 << 20
	sniffSize   = 8 << 10
	maxEvidence = 200
	findingSrc  = "rules"
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".next": true, "dist": true,
	"build": true, "vendor": true, ".venv": true, "__pycache__": true,
}

type repoState struct {
	first   *finding.Finding
	cleared bool
}

// Evaluate applies rs to the files under root. fsys supplies explain/fix text.
// It returns findings, non-fatal warnings, and an error only when root cannot be scanned.
func Evaluate(root string, stacks []string, rs []Rule, fsys fs.FS) ([]finding.Finding, []string, error) {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, nil, fmt.Errorf("대상 폴더를 열 수 없음: %s", root)
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	var active []Rule
	for _, r := range rs {
		if appliesTo(r, stacks) {
			active = append(active, r)
		}
	}
	var out []finding.Finding
	var warns []string
	repo := map[string]*repoState{}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: 읽지 못해 건너뜀: %v", finding.NormalizePath(root, p), err))
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
		if !d.Type().IsRegular() {
			return nil
		}
		rel := finding.NormalizePath(root, p)
		var cands []Rule
		for _, r := range active {
			if matchesFiles(r, rel) {
				cands = append(cands, r)
			}
		}
		if len(cands) == 0 {
			return nil
		}
		content, ok, warn := readText(p)
		if warn != "" {
			warns = append(warns, rel+": "+warn)
		}
		if !ok {
			return nil
		}
		for _, r := range cands {
			// Whole-file regexes are the slow part, so they run only when they can matter.
			missing := func() bool {
				return !containsAny(content, r.Match.MissingAll) && !matchesAny(content, r.missRe)
			}
			gated := func() bool { return matchesGlobs(r.Match.GateFiles, rel) && !matchesAny(content, r.gateRe) }
			required := containsAll(content, r.Match.RequireAll)
			switch r.Match.Scope {
			case "line":
				if required && !gated() && missing() {
					out = append(out, lineFindings(r, rel, content, stacks, fsys)...)
				}
			case "repo":
				if gated() {
					continue
				}
				line, text := 0, ""
				if required {
					line, text = firstRuleHit(content, r)
				}
				st := repo[r.ID]
				if st == nil {
					st = &repoState{}
					repo[r.ID] = st
				}
				if !missing() {
					st.cleared = true
				}
				if line > 0 && st.first == nil {
					f := build(r, rel, line, text, stacks, fsys)
					st.first = &f
				}
			default:
				if !required {
					continue
				}
				if line, text := firstRuleHit(content, r); line > 0 && !gated() && missing() {
					out = append(out, build(r, rel, line, text, stacks, fsys))
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, warns, err
	}
	for _, r := range active {
		if st := repo[r.ID]; st != nil && st.first != nil && !st.cleared {
			out = append(out, *st.first)
		}
	}
	finding.Sort(out)
	return out, warns, nil
}

func appliesTo(r Rule, stacks []string) bool {
	if len(r.Stacks) == 0 {
		return true
	}
	for _, rs := range r.Stacks {
		for _, s := range stacks {
			if rs == s {
				return true
			}
		}
	}
	return false
}

func matchesFiles(r Rule, rel string) bool {
	return matchesGlobs(r.Match.Files, rel) && !matchesGlobs(r.Match.ExcludeFiles, rel)
}

func matchesGlobs(pats []string, rel string) bool {
	for _, pat := range pats {
		// Load validates every pattern with ValidatePattern, so Match cannot
		// return an error here; if it ever did, treating it as no match is safe.
		if ok, err := doublestar.Match(pat, rel); err == nil && ok {
			return true
		}
	}
	return false
}

// readText returns the file text, or ok=false when it must be skipped.
func readText(p string) (content string, ok bool, warn string) {
	st, err := os.Stat(p)
	if err != nil {
		return "", false, "읽지 못해 건너뜀: " + err.Error()
	}
	if st.Size() > maxFileSize {
		return "", false, ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false, "읽지 못해 건너뜀: " + err.Error()
	}
	head := b
	if len(head) > sniffSize {
		head = head[:sniffSize]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return "", false, ""
	}
	return string(b), true, ""
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func containsAll(s string, subs []string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

func matchesAny(s string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// firstRuleHit returns the earliest line hit by has_any or has_any_regex.
func firstRuleHit(content string, r Rule) (int, string) {
	line, text := firstHit(content, r.Match.HasAny)
	if !regexAllowed(r, content) {
		return line, text
	}
	for _, re := range r.hasRe {
		loc := re.FindStringIndex(content)
		if loc == nil {
			continue
		}
		n := strings.Count(content[:loc[0]], "\n") + 1
		if line == 0 || n < line {
			start := strings.LastIndexByte(content[:loc[0]], '\n') + 1
			end := len(content)
			if i := strings.IndexByte(content[start:], '\n'); i >= 0 {
				end = start + i
			}
			line, text = n, strings.TrimSpace(content[start:end])
		}
	}
	return line, text
}

// lineFindings gives one finding per matching line, so ignoring one of them
// through its fingerprint leaves the others reported. Lines that look the same
// once masked are told apart by their order in the file (see numberRepeats),
// never by the value behind the mask. Masks apply to the matching too.
func lineFindings(r Rule, rel, content string, stacks []string, fsys fs.FS) []finding.Finding {
	var out []finding.Finding
	for i, l := range strings.Split(content, "\n") {
		allowed := regexAllowed(r, l)
		if !allowed && len(r.Match.HasAny) == 0 {
			continue
		}
		if matchesAny(l, r.skipRe) {
			continue
		}
		masked := l
		for _, re := range r.maskRe {
			masked = re.ReplaceAllString(masked, "${keep}")
		}
		if !containsAny(masked, r.Match.HasAny) && !(allowed && matchesAny(masked, r.hasRe)) {
			continue
		}
		out = append(out, build(r, rel, i+1, strings.TrimSpace(l), stacks, fsys))
	}
	numberRepeats(out)
	return out
}

// numberRepeats gives the findings of one rule in one file, which arrive in
// line order, their occurrence number: 0 for the first of a given evidence, 1 for
// the next, and so on, so two lines that look the same once masked keep two
// fingerprints without either depending on a value.
func numberRepeats(fs []finding.Finding) {
	seen := map[string]int{}
	for i := range fs {
		f := &fs[i]
		n := seen[f.Evidence]
		seen[f.Evidence] = n + 1
		f.Fingerprint = finding.MakeMaskedFingerprint(f.ID, f.Location, f.Evidence, n)
	}
}

// regexAllowed is the cheap literal test in front of has_any_regex.
func regexAllowed(r Rule, s string) bool {
	return len(r.Match.RegexRequires) == 0 || containsAny(s, r.Match.RegexRequires)
}

// firstHit returns the 1-based number and trimmed text of the first line containing any term.
func firstHit(content string, terms []string) (int, string) {
	if !containsAny(content, terms) {
		return 0, ""
	}
	for i, l := range strings.Split(content, "\n") {
		if containsAny(l, terms) {
			return i + 1, strings.TrimSpace(l)
		}
	}
	return 0, ""
}

func truncate(s string) string {
	if r := []rune(s); len(r) > maxEvidence {
		return string(r[:maxEvidence])
	}
	return s
}

// build makes a finding; text is the trimmed source line. Evidence is masked.
// The fingerprint comes from the evidence the report shows and the occurrence 0,
// never from the source line, so no part of a value is in it. A caller that
// sees the same evidence again in one file renumbers it (see numberRepeats).
func build(r Rule, rel string, line int, text string, stacks []string, fsys fs.FS) finding.Finding {
	conf := finding.Suspect
	if r.Confidence == "high" {
		conf = finding.Certain
	}
	evidence := truncate(maskEvidenceFor(rel, text))
	if r.HideValues {
		// Only the hidden form is kept: the name and what follows it, never a value.
		evidence = hideEvidence(text)
	}
	f := finding.Finding{
		Kind: r.ID,
		ID:   r.ID, Source: findingSrc, Severity: r.severity, Confidence: conf,
		Location: rel, Line: line, Evidence: truncate(evidence), Title: r.Title,
		Fingerprint: finding.MakeMaskedFingerprint(r.ID, rel, truncate(evidence), 0),
	}
	if r.Explain != "" {
		if b, err := fs.ReadFile(fsys, r.Explain); err == nil {
			f.ExplainKo = string(b)
		}
	}
	if r.Fix != "" {
		f.Fix = readFix(fsys, path.Clean(r.Fix), rel, stacks)
	}
	for _, ref := range r.References {
		f.References = append(f.References, ref.URL)
	}
	for _, m := range r.Mappings {
		f.Mappings = append(f.Mappings, finding.Mapping{ID: m})
	}
	return f
}

// readFix picks the guide for the language of the file the finding is in, so a
// monorepo doesn't show a PHP guide on a .tsx file or the other way round.
// Files of other languages follow the stack order, with the JavaScript stacks
// ahead of php and fastapi.
func readFix(fsys fs.FS, dir, rel string, stacks []string) string {
	var order []string
	switch strings.ToLower(path.Ext(rel)) {
	case ".php", ".phtml":
		order = append(order, "php")
	case ".py":
		order = append(order, "fastapi")
	default:
		for _, s := range stacks {
			if s != "php" && s != "fastapi" {
				order = append(order, s)
			}
		}
	}
	for _, s := range append(order, stacks...) {
		if b, err := fs.ReadFile(fsys, path.Join(dir, s+".md")); err == nil {
			return string(b)
		}
	}
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if !e.IsDir() {
			if b, err := fs.ReadFile(fsys, path.Join(dir, e.Name())); err == nil {
				return string(b)
			}
		}
	}
	return ""
}

// SkipDir reports whether a directory of this name is left out of repository
// walks (dependencies, build output, VCS data).
func SkipDir(name string) bool { return skipDirs[name] }
