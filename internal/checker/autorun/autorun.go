// Package autorun lists the commands that a repository's own configuration
// files arrange to run automatically (VS Code tasks, dev containers, MCP
// servers, Claude Code hooks and helpers, npm install scripts).
//
// It only reads JSON files. Nothing from the scanned repository is executed,
// evaluated or followed through a symbolic link, and every string it reads is
// treated as untrusted text.
package autorun

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/ignore"
	"github.com/iimmuunnee/ai-defense-kit/internal/rules"
)

// CheckerName is the name this checker reports under.
const CheckerName = "autorun"

const (
	maxFileSize = 1 << 20
	maxText     = 1000
	unreadable  = "파일을 해석하지 못했습니다. 직접 확인하세요."
	notUsedText = ": --untrusted로 이 파일을 쓰지 않았습니다."
	tooManyText = "자동 실행 항목이 너무 많아 일부만 보여 줍니다. 파일을 직접 확인하세요."
)

type autorunChecker struct{ data fs.FS }

// New returns the autorun checker. data supplies explain/AR-00N.md; a nil or
// incomplete data set gives findings with empty explanations.
func New(data fs.FS) checker.Checker { return autorunChecker{data: data} }

func (autorunChecker) Name() string { return CheckerName }

type fileKind int

const (
	kindNone fileKind = iota
	kindTasks
	kindDevcontainer
	kindMCP
	kindSettings
	kindPackage
)

// classify decides by the lower-cased path pieces, so .VSCode/Tasks.JSON counts.
func classify(rel string) fileKind {
	p := strings.Split(strings.ToLower(rel), "/")
	n := len(p)
	last := p[n-1]
	parent := func(i int) string { // i-th directory above the file, 1 = direct parent
		if n-1-i < 0 {
			return ""
		}
		return p[n-1-i]
	}
	switch {
	case last == "tasks.json" && parent(1) == ".vscode":
		return kindTasks
	case last == ".devcontainer.json",
		last == "devcontainer.json" && parent(1) == ".devcontainer",
		last == "devcontainer.json" && parent(2) == ".devcontainer":
		return kindDevcontainer
	case last == ".mcp.json", last == "mcp.json" && (parent(1) == ".cursor" || parent(1) == ".vscode"):
		return kindMCP
	case (last == "settings.json" || last == "settings.local.json") && parent(1) == ".claude":
		return kindSettings
	case last == "package.json":
		return kindPackage
	}
	return kindNone
}

// unreadableID is the finding number used when a file of this kind cannot be read.
func (k fileKind) unreadableID() string {
	switch k {
	case kindTasks:
		return "AR-001"
	case kindDevcontainer:
		return "AR-002"
	case kindPackage:
		return "AR-005"
	}
	return "AR-004"
}

func severityOf(id string) finding.Severity {
	switch id {
	case "AR-001", "AR-002":
		return finding.High
	case "AR-003", "AR-004":
		return finding.Medium
	}
	return finding.Low
}

func confidenceOf(id string) finding.Confidence {
	if id == "AR-001" || id == "AR-002" || id == "AR-006" {
		return finding.Certain
	}
	return finding.Suspect
}

// titleOf gives a fixed title per number. It never carries repository text, so
// a label cannot turn into a link or a heading in a report; the item name is
// shown in the evidence instead.
func titleOf(id string) string {
	switch id {
	case "AR-001":
		return "자동 실행되도록 설정된 VS Code 작업"
	case "AR-002":
		return "개발 컨테이너를 만들 때 실행되는 initializeCommand"
	case "AR-003":
		return "개발 컨테이너를 만들거나 시작할 때 실행되는 명령"
	case "AR-004":
		return "AI 도구가 실행하거나 연결할 수 있는 설정(MCP 서버, 훅, 도우미 명령)"
	case "AR-006":
		return "결과를 숨길 수 있는 설정 파일"
	}
	return "패키지 설치 때 실행되는 스크립트"
}

const unreadableTitle = "자동 실행 설정 파일을 확인하지 못함"

// hidingFile reports a file that can change what a scan shows: .adkignore, read
// only from the scan root, and osv-scanner.toml, read from the folder of each
// lockfile. Other names were tried and change nothing (.osv-scanner.toml,
// .gitleaksignore, .gitleaks.toml). p is its path, rel the same from the root.
func hidingFile(p, rel string) bool {
	return strings.EqualFold(rel, ignore.FileName) && isReadAs(p, ignore.FileName) || isOSVConfig(p)
}

func isOSVConfig(p string) bool {
	const name = "osv-scanner.toml"
	return strings.EqualFold(filepath.Base(p), name) && isReadAs(p, name)
}

// isReadAs reports that opening the exact name beside p gets p. A name differing
// only in case is the same file on some file systems and no file on others.
func isReadAs(p, name string) bool {
	if filepath.Base(p) == name {
		return true
	}
	a, err := os.Lstat(p)
	if err != nil {
		return false
	}
	b, err := os.Lstat(filepath.Join(filepath.Dir(p), name))
	return err == nil && os.SameFile(a, b)
}

// configDirKind recognizes the directories whose contents are read as
// configuration, so a link or a read error on one cannot hide what is in it.
func configDirKind(rel string) fileKind {
	p := strings.Split(strings.ToLower(rel), "/")
	n := len(p)
	switch p[n-1] {
	case ".vscode":
		return kindTasks
	case ".devcontainer":
		return kindDevcontainer
	case ".cursor", ".claude":
		return kindMCP
	}
	if n >= 2 && p[n-2] == ".devcontainer" {
		return kindDevcontainer
	}
	return kindNone
}

func referencesOf(id string, kind fileKind, rel string) []string {
	switch id {
	case "AR-006":
		return nil
	case "AR-001":
		return []string{"https://code.visualstudio.com/docs/debugtest/tasks"}
	case "AR-002", "AR-003":
		return []string{"https://containers.dev/implementors/json_reference/"}
	case "AR-005":
		return []string{"https://docs.npmjs.com/cli/v11/using-npm/scripts"}
	}
	switch kind {
	case kindSettings:
		return []string{"https://code.claude.com/docs/en/hooks.md", "https://code.claude.com/docs/en/settings-reference.md"}
	case kindMCP:
		lower := strings.ToLower(rel)
		if strings.HasSuffix(lower, ".cursor/mcp.json") {
			return []string{"https://cursor.com/docs/context/mcp"}
		}
		if strings.HasSuffix(lower, ".vscode/mcp.json") {
			return []string{"https://code.visualstudio.com/docs/agents/run/manage-mcp-servers"}
		}
	}
	return []string{"https://code.claude.com/docs/en/mcp.md"}
}

func (c autorunChecker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	var res checker.Result
	root := t.Root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	explain := map[string]string{}
	seen := map[string]bool{}

	add := func(id string, kind fileKind, sev finding.Severity, conf finding.Confidence, rel, title, evidence, fp string) {
		if seen[fp] {
			return
		}
		seen[fp] = true
		text, ok := explain[id]
		if !ok {
			text = c.read("explain/" + id + ".md")
			explain[id] = text
		}
		res.Findings = append(res.Findings, finding.Finding{
			ID:          id,
			Source:      CheckerName,
			Kind:        id,
			Severity:    sev,
			Confidence:  conf,
			Location:    locationText(rel),
			Line:        0,
			Evidence:    evidence,
			Title:       title,
			ExplainKo:   text,
			References:  referencesOf(id, kind, rel),
			Fingerprint: fp,
		})
	}
	addUnreadable := func(kind fileKind, rel, reason string) {
		id := kind.unreadableID()
		add(id, kind, severityOf(id), finding.Suspect, rel, unreadableTitle, unreadable, finding.MakeFingerprint(id, rel, reason+"\x00"))
	}
	// The file is named, never opened. Its fingerprint is the same with or without
	// the flag.
	addHiding := func(rel string) {
		const id = "AR-006"
		evidence := clean(path.Base(rel))
		if t.Untrusted {
			evidence += notUsedText
		}
		add(id, kindNone, severityOf(id), confidenceOf(id), rel, titleOf(id), evidence, finding.MakeFingerprint(id, rel, "hiding\x00"))
	}
	// osv-scanner also reads the folders this walk skips, and a config there works
	// for the lockfile beside it. Nothing else in them is looked at.
	findOSVConfigs := func(dir string) error {
		return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			rel := finding.NormalizePath(root, p)
			switch {
			case err != nil:
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: 읽지 못해 건너뜀: %v", locationText(rel), err))
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
			case d.IsDir():
				if strings.EqualFold(d.Name(), ".git") {
					return fs.SkipDir
				}
			case isOSVConfig(p):
				addHiding(rel)
			}
			return nil
		})
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		rel := finding.NormalizePath(root, p)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: 읽지 못해 건너뜀: %v", locationText(rel), err))
			if d != nil && d.IsDir() {
				if k := configDirKind(rel); k != kindNone && p != root {
					addUnreadable(k, rel, "unreadable")
				}
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			// A folder directly under .devcontainer holds its own devcontainer.json
			// whatever it is called, so it is entered even when its name is on the
			// skip list; inside it only that one file is looked at.
			switch {
			case p == root:
			case exemptDevcontainerDir(rel):
			case rules.SkipDir(d.Name()), exemptDevcontainerDir(path.Dir(rel)):
				if err := findOSVConfigs(p); err != nil {
					return err
				}
				return fs.SkipDir
			}
			return nil
		}
		if hidingFile(p, rel) {
			addHiding(rel)
			return nil
		}
		if exemptDevcontainerDir(path.Dir(rel)) && !strings.EqualFold(d.Name(), "devcontainer.json") {
			return nil
		}
		kind := classify(rel)
		if kind == kindNone && !d.Type().IsRegular() {
			// A link or a Windows junction in place of a config directory would hide
			// everything in it.
			if k := configDirKind(rel); k != kindNone {
				switch strings.ToLower(d.Name()) {
				case ".vscode", ".devcontainer", ".cursor", ".claude":
					kind = k
				default: // a link directly under .devcontainer: only a folder link matters
					if st, serr := os.Stat(p); serr != nil || st.IsDir() {
						kind = k
					}
				}
			}
		}
		if kind == kindNone {
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			addUnreadable(kind, rel, "symlink")
			return nil
		case !d.Type().IsRegular():
			addUnreadable(kind, rel, "unreadable")
			return nil
		}
		b, reason := readCapped(p)
		if reason != "" {
			addUnreadable(kind, rel, reason)
			return nil
		}
		obj, derr := decodeObject(b)
		if derr != nil {
			addUnreadable(kind, rel, "unreadable")
			return nil
		}
		col := &collector{ctx: ctx, fileHasKey: holdsKeyBlock(obj)}
		col.parse(kind, obj)
		if col.err != nil {
			return col.err
		}
		es := col.out
		tooMany := col.tooMany()
		if len(es) > maxFindings {
			es = es[:maxFindings]
		}
		// The fingerprint comes from the evidence the report shows, never from the
		// file's own text (not even a name: a label or script name can hold a value
		// the evidence masks), so a masked or cut part is in no fingerprint. The
		// same evidence twice in a file is told apart by its order.
		repeats := map[string]int{}
		var top entry
		for _, e := range es {
			rk := e.id + "\x00" + e.evidence
			n := repeats[rk]
			repeats[rk] = n + 1
			sev, conf := severityOf(e.id), confidenceOf(e.id)
			if e.keyBlock { // abnormal in a setting that runs, and it may hide a command
				sev, conf = max(sev, finding.High), finding.Suspect
			}
			add(e.id, kind, sev, conf, rel, titleOf(e.id), e.evidence,
				finding.MakeMaskedFingerprint(e.id, rel, e.evidence, n))
			if top.id == "" || severityOf(e.id) > severityOf(top.id) {
				top = e
			}
		}
		if tooMany {
			id := top.id
			if id == "" {
				id = kind.unreadableID()
			}
			add(id, kind, severityOf(id), finding.Suspect, rel, unreadableTitle, tooManyText, finding.MakeFingerprint(id, rel, "too-many\x00"))
		}
		return nil
	})
	if err != nil {
		return checker.Result{}, err
	}
	return res, nil
}

func (c *collector) parse(kind fileKind, obj map[string]any) {
	switch kind {
	case kindTasks:
		c.parseTasks(obj)
	case kindDevcontainer:
		c.parseDevcontainer(obj)
	case kindMCP:
		c.parseMCP(obj)
	case kindSettings:
		c.parseSettings(obj)
	case kindPackage:
		c.parsePackage(obj)
	}
}

func (c autorunChecker) read(name string) string {
	if c.data == nil {
		return ""
	}
	b, err := fs.ReadFile(c.data, name)
	if err != nil {
		return ""
	}
	return string(b)
}

// readCapped reads a regular file of at most maxFileSize bytes. The second
// result is empty on success, else the reason key: "too-large" or "unreadable".
func readCapped(p string) ([]byte, string) {
	f, err := os.Open(p)
	if err != nil {
		return nil, "unreadable"
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, "unreadable"
	}
	if len(b) > maxFileSize {
		return nil, "too-large"
	}
	return b, ""
}

// clean removes control, C1 and Unicode format characters (which include the
// bidirectional controls), turns line breaks into spaces and backticks into
// apostrophes, so repository text cannot reshape a terminal line or Markdown.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == '\u2028' || r == '\u2029':
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

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// window cuts finished text at maxText characters with a visible marker, and
// adds the marker when masking already left text out.
func window(s string, cut bool) string {
	r := []rune(s)
	switch {
	case len(r) > maxText:
		return string(r[:maxText]) + cutNotice
	case cut:
		return s + cutNotice
	}
	return s
}

// locationText is a path as shown in a report: control characters removed and
// nothing else changed, so a long path cannot be made to look like another one.
func locationText(rel string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, rel)
}

// exemptDevcontainerDir reports <anything>/.devcontainer/<one folder> whose
// name is on the skip list (dist, build, vendor ...). Such a folder is a dev
// container folder, not a dependency directory. rel is relative to the scan
// root, so a root that is itself called .devcontainer gets no exemption.
func exemptDevcontainerDir(rel string) bool {
	p := strings.Split(rel, "/")
	n := len(p)
	return n >= 2 && strings.EqualFold(p[n-2], ".devcontainer") && rules.SkipDir(p[n-1])
}

const cutNotice = "… (잘림, 파일을 직접 확인하세요)"
