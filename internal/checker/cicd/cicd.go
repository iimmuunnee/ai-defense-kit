// Package cicd checks GitHub Actions workflows (.github/workflows at the scan
// root) for deployment paths that hold long-lived cloud keys, run actions that
// are not pinned to a commit, hand out broad GITHUB_TOKEN permissions or check
// out pull request code under pull_request_target.
//
// It only reads the YAML text. Nothing from the scanned repository is run or
// followed through a symbolic link, no connection is made, and the value of a
// key is never copied into a result: only the key's name, the file and the
// line are.
package cicd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// CheckerName is the name this checker reports under.
const CheckerName = "cicd"

const (
	maxFileSize = 1 << 20 // 1MB, as the other checkers
	maxEvidence = 300
	maxFindings = 200 // per file, as autorun
	workflowDir = ".github/workflows"
)

type cicdChecker struct{ data fs.FS }

// New returns the cicd checker. data supplies explain/CI-00N.md and
// fixes/CI-00N/github-actions.md; a nil or incomplete data set gives findings
// with empty texts.
func New(data fs.FS) checker.Checker { return cicdChecker{data: data} }

func (cicdChecker) Name() string { return CheckerName }

var references = map[string][]string{
	"CI-001": {
		"https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services",
		"https://github.com/aws-actions/configure-aws-credentials",
	},
	"CI-002": {"https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"},
	"CI-003": {"https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token"},
	"CI-004": {"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"},
	"CI-005": nil,
}

func (c cicdChecker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	var res checker.Result
	if err := ctx.Err(); err != nil {
		return checker.Result{}, err
	}
	root := t.Root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	dir := filepath.Join(root, ".github", "workflows")
	texts := map[string][2]string{}

	emit := func(h hit, rel, fp string) {
		tx, ok := texts[h.id]
		if !ok {
			tx = [2]string{c.read("explain/" + h.id + ".md"), c.read("fixes/" + h.id + "/github-actions.md")}
			texts[h.id] = tx
		}
		res.Findings = append(res.Findings, finding.Finding{
			ID:          h.id,
			Source:      CheckerName,
			Kind:        h.id,
			Severity:    h.severity,
			Confidence:  h.confidence,
			Location:    locationText(rel),
			Line:        h.line,
			Evidence:    cut(clean(h.evidence), maxEvidence), // fragments were scanned before the sentence was made (see shown)
			Title:       h.title,
			ExplainKo:   tx[0],
			Fix:         tx[1],
			References:  references[h.id],
			Fingerprint: fp,
		})
	}
	// unread reports a file or folder that was not read. It is a result and a
	// warning: a warning alone never reaches the exit code.
	unread := func(rel, reason, evidence string) {
		res.Warnings = append(res.Warnings, locationText(rel)+": "+evidence+" 직접 확인하세요.")
		emit(hit{id: "CI-005", severity: finding.Medium, confidence: finding.Suspect, title: titleUnread, evidence: evidence},
			rel, finding.MakeFingerprint("CI-005", rel, reason))
	}

	// A link in place of either folder would point the read somewhere else.
	for _, p := range []string{filepath.Join(root, ".github"), dir} {
		fi, err := os.Lstat(p)
		rel := finding.NormalizePath(root, p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return res, nil
		case err != nil:
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: 읽지 못해 건너뜀: %s", workflowDir, clean(err.Error())))
			return res, nil
		case fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			unread(rel, "symlink", "링크라서 읽지 않았습니다.")
			return res, nil
		case !fi.IsDir():
			return res, nil
		}
	}

	entries, err := os.ReadDir(dir) // sorted by file name
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s 폴더를 읽지 못했습니다: %s", workflowDir, clean(err.Error())))
		return res, nil
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return checker.Result{}, err
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		rel := path.Join(workflowDir, e.Name())
		shown := locationText(rel)
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			unread(rel, "symlink", "링크라서 읽지 않았습니다.")
			continue
		case !e.Type().IsRegular():
			unread(rel, "not-regular", "일반 파일이 아니라 읽지 않았습니다.")
			continue
		}
		b, tooLarge, err := readCapped(filepath.Join(dir, e.Name()))
		switch {
		case tooLarge:
			unread(rel, "too-large", "1MB보다 커서 읽지 않았습니다.")
			continue
		case err != nil:
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: 읽지 못해 건너뜀: %s", shown, clean(err.Error())))
			continue
		}
		hits, warns := analyzeFile(b)
		for _, w := range warns {
			res.Warnings = append(res.Warnings, shown+": "+w)
		}
		// Keep the most serious when there are too many, so a flood of low
		// results cannot push a critical one out.
		tooMany := len(hits) > maxFindings
		if tooMany {
			sort.SliceStable(hits, func(i, j int) bool { return hits[i].severity > hits[j].severity })
			hits = hits[:maxFindings]
		}
		seen := map[string]int{}
		for _, h := range hits {
			base := finding.MakeFingerprint(h.id, rel, h.key)
			// The same item twice in a file stays two results, told apart by order.
			seen[base]++
			fp := base
			if n := seen[base]; n > 1 {
				fp = finding.MakeFingerprint(h.id, rel, fmt.Sprintf("%s\x00#%d", h.key, n))
			}
			emit(h, rel, fp)
		}
		if tooMany {
			ev := fmt.Sprintf("결과가 %d건을 넘어 심각한 순서로 %d건만 보여 줍니다.", maxFindings, maxFindings)
			res.Warnings = append(res.Warnings, shown+": "+ev+" 직접 확인하세요.")
			emit(hit{id: "CI-005", severity: finding.Medium, confidence: finding.Suspect, title: titleUnread, evidence: ev},
				rel, finding.MakeFingerprint("CI-005", rel, "too-many"))
		}
	}
	return res, nil
}

func (c cicdChecker) read(name string) string {
	if c.data == nil {
		return ""
	}
	b, err := fs.ReadFile(c.data, name)
	if err != nil {
		return ""
	}
	return string(b)
}

// readCapped reads at most maxFileSize bytes; tooLarge is set when there is more.
func readCapped(p string) (b []byte, tooLarge bool, err error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	b, err = io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxFileSize {
		return nil, true, nil
	}
	return b, false, nil
}

// analyzeFile parses every YAML document in b and returns what it found. A
// parse error ends the reading of the file but keeps what came before it.
func analyzeFile(b []byte) (hits []hit, warns []string) {
	a := &analyzer{budget: maxVisits}
	defer func() {
		if r := recover(); r != nil {
			hits = a.hits
			warns = append(warns, "해석 중 오류가 나 일부만 점검했습니다. 직접 확인하세요.")
		}
	}()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			warns = append(warns, "YAML을 해석하지 못해 이후 내용을 건너뜀: "+cut(clean(err.Error()), 200)+". 직접 확인하세요.")
			break
		}
		a.document(&doc)
	}
	if a.exceeded {
		warns = append(warns, "구조가 너무 커서 일부만 점검했습니다. 직접 확인하세요.")
	}
	return a.hits, warns
}

// clean removes control and Unicode format characters (which include the
// bidirectional controls), turns line breaks into spaces and backticks into
// apostrophes, so repository text cannot reshape a terminal line or Markdown.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == ' ':
			b.WriteByte(' ')
		case r == '`':
			b.WriteByte('\'')
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// shown is how a fragment of the workflow (a job or service name, a uses
// value) is put into evidence: cleaned, then scanned on its own by the value
// rule (finding.ScrubValueText), before it is joined with the tool's own
// words. It is scanned both before and after cleaning, so a format character
// can neither split a phrase nor be removed to join one.
func shown(s string) string { return finding.ScrubValueText(clean(finding.ScrubValue(s))) }

// cut shortens s to n characters with a visible marker.
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "… (잘림, 파일을 직접 확인하세요)"
}

// locationText is a path as shown in a report: control characters removed.
func locationText(rel string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, rel)
}
