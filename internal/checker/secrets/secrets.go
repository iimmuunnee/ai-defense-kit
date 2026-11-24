// Package secrets finds hard-coded secrets in current files and git history
// using gitleaks as a library. gitleaks types never leave this package.
package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/rs/zerolog"
	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	glregexp "github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	maxFileSize = 1 << 20 // 1MB
	// historyMaxSize is the largest single change the history scan checks.
	// Larger than maxFileSize so that a committed bundle over 1MB is still
	// checked once; see sizeLimited.
	historyMaxSize = 5 << 20 // 5MB
	// fileDecodeDepth is how many times the current-file scan decodes base64,
	// hex, percent and unicode-escaped text before matching (gitleaks' own
	// program uses 5). One pass found the same keys as five on the repositories
	// measured. History is left undecoded: decoding it made the check about a
	// third slower on a 24,000-commit repository, while decoding current files
	// cost nothing measurable.
	fileDecodeDepth    = 1
	warnNoGit          = "git 기록이 없어 과거 커밋은 확인하지 못했습니다."
	warnHistoryPartial = "git 기록을 읽지 못해 과거 커밋 일부는 확인하지 못했습니다 (git 오류 또는 빠진 객체)."
	// warnHistoryUnfinished goes with the current-file results saved before the
	// history scan starts: it is shown only if the timeout stops that scan.
	warnHistoryUnfinished = "시간 제한 안에 git 기록(과거 커밋)을 다 보지 못했습니다. 현재 파일 결과만 담았고, 과거 커밋에만 남은 비밀 키는 빠졌을 수 있습니다."
	gitLogOpts            = "--full-history --all --diff-filter=tuxdb --no-textconv --no-ext-diff --no-show-signature --relative"
)

type secretsChecker struct{ data fs.FS }

// New returns the secrets checker. data supplies explain/kinds/*.md.
func New(data fs.FS) checker.Checker {
	quietOnce.Do(func() { zerolog.SetGlobalLevel(zerolog.Disabled) }) // gitleaks logs through zerolog
	return secretsChecker{data: data}
}

var quietOnce sync.Once

func (secretsChecker) Name() string { return "secrets" }

func (c secretsChecker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	root, err := filepath.Abs(t.Root)
	if err != nil {
		return checker.Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return checker.Result{}, err
	}

	current, err := fileScanner(ctx, root, t.Untrusted)
	if err != nil {
		return checker.Result{}, fmt.Errorf("현재 파일 점검 실패: %w", err)
	}
	current = dropPublicSupabaseKeys(current)
	explainCur, explainHist := c.explain("secret-current.md"), c.explain("secret-history.md")

	// Under --untrusted the scanned repository's own .gitignore must not lower
	// a finding, so every current-file key stays high there.
	local := map[string]bool{}
	if hasGit(root) && !t.Untrusted {
		var locs []string
		for _, g := range current {
			locs = append(locs, finding.NormalizePath(root, g.File))
		}
		local = localOnly(ctx, root, locs)
	}
	explainLocal := c.explain("secret-local.md")

	var res checker.Result
	var history []report.Finding
	if hasGit(root) {
		// The history scan is the slow stage. If the timeout stops it, the
		// current-file results still reach the report, with a warning.
		partial := merge(root, current, nil, explainCur, explainHist)
		markLocal(partial, local, explainLocal)
		checker.SavePartial(ctx, checker.Result{
			Findings: partial,
			Warnings: []string{warnHistoryUnfinished},
		})
		var hs historyScan
		hs, err = historyScanner(ctx, root, t.Untrusted)
		history = hs.Findings
		if err == nil && hs.Partial {
			res.Warnings = append(res.Warnings, warnHistoryPartial)
		}
		if err == nil && len(hs.SkippedLarge) > 0 {
			res.Warnings = append(res.Warnings, skippedLargeWarning(hs.SkippedLarge))
		}
		if err != nil {
			if ctx.Err() != nil {
				return checker.Result{}, ctx.Err()
			}
			res.Warnings = append(res.Warnings, "git 기록을 읽지 못해 과거 커밋은 확인하지 못했습니다.")
			history = nil
		}
	} else {
		res.Warnings = append(res.Warnings, warnNoGit)
	}

	history = dropPublicSupabaseKeys(history)

	res.Findings = merge(root, current, history, explainCur, explainHist)
	markLocal(res.Findings, local, explainLocal)
	return res, nil
}

// fileScanner and historyScanner are the two stages of Run. Tests replace them.
var (
	fileScanner    = scanFiles
	historyScanner = scanHistory
)

// merge turns gitleaks' current-file and history findings into adk findings.
// A secret already found in a current file is not repeated from history, and a
// secret found in several history places is reported once.
func merge(root string, current, history []report.Finding, explainCur, explainHist string) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	curLoc := func(g report.Finding) string { return finding.NormalizePath(root, g.File) }
	var curPos, histPos [][2]int
	for _, g := range current {
		k := g.RuleID + "\x00" + g.Secret
		loc := curLoc(g)
		seen[k] = true
		out = append(out, build(g, "secret-current", loc, finding.High, titleCurrent, g.Secret, "", explainCur,
			"코드에서 키를 지우고 환경 변수로 옮긴 뒤, 이미 공유된 적이 있다면 키를 폐기하고 새로 발급하세요."))
		curPos = append(curPos, [2]int{g.StartLine, g.StartColumn})
	}
	nCur := len(out)
	for _, g := range historyInOrder(history) {
		k := g.RuleID + "\x00" + g.Secret
		if seen[k] {
			continue
		}
		seen[k] = true
		commit := g.Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		out = append(out, build(g, "secret-history", filepath.ToSlash(g.File), finding.Medium, "git 기록에 비밀 키가 남아 있음", g.Secret,
			" (커밋 "+commit+")", explainHist,
			"파일을 지워도 기록에 남습니다. 해당 키를 폐기하고 새로 발급하세요."))
		histPos = append(histPos, [2]int{g.StartLine, g.StartColumn})
	}
	numberRepeats(out[:nCur], curPos)
	numberRepeats(out[nCur:], histPos)
	return out
}

// historyInOrder returns history sorted so the place merge keeps for a secret
// found in several commits or files is the same on every run. gitleaks checks
// each file change of the log in its own goroutine and appends findings as they
// finish, so its order changes from run to run; keeping "the first one" in that
// order moved the reported file, commit and fingerprint between runs.
//
// The oldest commit comes first (gitleaks gives the author date as UTC RFC 3339,
// so the strings compare as times), then path, line, column and commit hash. The
// oldest commit is where the secret got in, and new commits that copy it later do
// not move it, so the fingerprint stays put while the history grows. A missing
// date sorts last.
func historyInOrder(history []report.Finding) []report.Finding {
	out := slices.Clone(history)
	slices.SortStableFunc(out, func(a, b report.Finding) int {
		if (a.Date == "") != (b.Date == "") {
			if a.Date == "" {
				return 1
			}
			return -1
		}
		if c := strings.Compare(a.Date, b.Date); c != 0 {
			return c
		}
		if c := strings.Compare(filepath.ToSlash(a.File), filepath.ToSlash(b.File)); c != 0 {
			return c
		}
		if c := a.StartLine - b.StartLine; c != 0 {
			return c
		}
		if c := a.StartColumn - b.StartColumn; c != 0 {
			return c
		}
		return strings.Compare(a.Commit, b.Commit)
	})
	return out
}

// numberRepeats gives the findings of one scan part their occurrence number:
// for the same rule, file and shown evidence, 0 for the first in line order
// (line, then column), 1 for the next, and so on. The number neither follows the
// order gitleaks returns findings in nor depends on a value. pos holds each
// finding's start line and column.
func numberRepeats(fs []finding.Finding, pos [][2]int) {
	idx := make([]int, len(fs))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		if c := pos[a][0] - pos[b][0]; c != 0 {
			return c
		}
		return pos[a][1] - pos[b][1]
	})
	seen := map[string]int{}
	for _, i := range idx {
		f := &fs[i]
		k := f.ID + "\x00" + f.Location + "\x00" + f.Evidence
		f.Fingerprint = finding.MakeMaskedFingerprint(f.ID, f.Location, f.Evidence, seen[k])
		seen[k]++
	}
}

func build(g report.Finding, kind, loc string, sev finding.Severity, title, secret, evSuffix, explain, fix string) finding.Finding {
	id := "SECRET-" + g.RuleID
	// The fingerprint comes from the evidence the report shows, never from the
	// secret: a 4-character prefix can be guessed back from a published hash.
	// numberRepeats gives the occurrence number once all findings are known.
	// A decoded value is not in the file as shown, so the evidence and the title
	// say so. The different evidence text also keeps a decoded finding from
	// taking the occurrence number of a plain one with the same masked value.
	note, tail := decodedNote(g.Tags)
	evidence := finding.Redact(secret) + tail + evSuffix
	conf, fullTitle := finding.Certain, title+" ("+g.RuleID+")"
	if note != "" {
		fullTitle += " - " + note
	}
	if why := lowerReason(loc, g); why != "" {
		conf, fullTitle = finding.Suspect, fullTitle+" - "+why
	}
	return finding.Finding{
		ID:          id,
		Source:      "secrets",
		Kind:        kind,
		Severity:    sev,
		Confidence:  conf,
		Location:    loc,
		Line:        g.StartLine,
		Evidence:    evidence,
		Title:       fullTitle,
		ExplainKo:   explain,
		Fix:         fix,
		Fingerprint: finding.MakeMaskedFingerprint(id, loc, evidence, 0),
	}
}

func (c secretsChecker) explain(name string) string {
	if c.data == nil {
		return ""
	}
	b, err := fs.ReadFile(c.data, "explain/kinds/"+name)
	if err != nil {
		return ""
	}
	return string(b)
}

// skippedDirs are folders that hold tool output or third-party code, the
// same set the rule engine skips. A .venv covers the Windows .venv/Lib layout.
const skippedDirs = `(?:\.git|node_modules|\.next|dist|build|vendor|\.venv|__pycache__)`

// detectorMu serialises building gitleaks' default detector, which reads its
// configuration through global viper. Checkers run in parallel.
var detectorMu sync.Mutex

func newDefaultDetector() (*detect.Detector, error) {
	detectorMu.Lock()
	defer detectorMu.Unlock()
	return detect.NewDetectorDefaultConfig()
}

// newDetector returns gitleaks' default detector plus a path allowlist for
// skippedDirs. prefix anchors the pattern: the slash-separated absolute root
// for file scans (so the root's own ancestors never count), "" for git
// history, whose paths are relative. With untrusted, a gitleaks:allow comment in
// the scanned code exempts nothing.
func newDetector(prefix string, untrusted bool) (*detect.Detector, error) {
	d, err := newDefaultDetector()
	if err != nil {
		return nil, err
	}
	d.IgnoreGitleaksAllow = untrusted
	start := "^"
	if prefix != "" {
		start += regexp.QuoteMeta(prefix) + "/"
	}
	a := &config.Allowlist{
		Description: "adk: build output and dependency folders",
		Paths:       []*glregexp.Regexp{glregexp.MustCompile(start + `(?:.*/)?` + skippedDirs + `(?:/.*)?$`)},
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	d.Config.Allowlists = append(d.Config.Allowlists, a)
	return d, nil
}

func scanFiles(ctx context.Context, root string, untrusted bool) ([]report.Finding, error) {
	d, err := newDetector(filepath.ToSlash(root), untrusted)
	if err != nil {
		return nil, err
	}
	d.MaxDecodeDepth = fileDecodeDepth
	return d.DetectSource(ctx, &sources.Files{
		Path:        root,
		Config:      &d.Config,
		Sema:        d.Sema,
		MaxFileSize: maxFileSize,
	})
}

// historyScan is what scanHistory found. Partial reports that git wrote an
// error while gitleaks read the log: gitleaks then stops reading and only logs
// it. SkippedLarge lists the paths whose changes were too big to check.
type historyScan struct {
	Findings     []report.Finding
	Partial      bool
	SkippedLarge []string
}

// scanHistory scans git history.
func scanHistory(ctx context.Context, root string, untrusted bool) (hs historyScan, err error) {
	if _, err := exec.LookPath("git"); err != nil {
		return hs, err
	}
	d, err := newDetector("", untrusted)
	if err != nil {
		return hs, err
	}
	opts, config, env := gitLogOpts, safeGitConfig, safeGitEnv
	if untrusted {
		opts += untrustedLogOpts
		config = slices.Concat(config, untrustedGitConfig)
		env = slices.Concat(env, untrustedGitEnv)
	}
	err = withGitSettings(config, env, func() error {
		// gitleaks' default log options plus --no-textconv/--no-ext-diff/
		// --no-show-signature, so a scanned repo's .git/config cannot make us
		// run its commands. --relative keeps a subfolder scan to that folder
		// and its paths relative to root.
		cmd, err := sources.NewGitLogCmdContext(ctx, root, opts)
		if err != nil {
			return err
		}
		tracked := &errTracking{inner: &sources.Git{
			Cmd:    cmd,
			Config: &d.Config,
			Sema:   d.Sema,
			Remote: &sources.RemoteInfo{Platform: scm.NoPlatform}, // no links, no remote lookups
		}}
		src := &sizeLimited{inner: tracked, max: historyMaxSize, allow: d.Config.Allowlists}
		hs.Findings, err = d.DetectSource(ctx, src)
		hs.Partial = tracked.failed.Load()
		hs.SkippedLarge = src.skippedPaths()
		return err
	})
	return hs, err
}

// sizeLimited drops history changes bigger than max before gitleaks checks
// them, as sources.Files does for current files. gitleaks sets no size limit
// on git history, and its cost grows with the size of a change and with how
// random its text looks (base64 data: about 6-10 seconds per MB): one 25MB
// HTML page with an inline image took over seven minutes.
// Paths the scan never checks anyway (the global path allowlists, such as
// dependency folders) are passed on, so only the rest are listed as skipped.
type sizeLimited struct {
	inner sources.Source
	max   int
	allow []*config.Allowlist

	mu      sync.Mutex
	skipped map[string]bool
}

func (s *sizeLimited) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return s.inner.Fragments(ctx, func(f sources.Fragment, err error) error {
		if err != nil || len(f.Raw) <= s.max || s.pathAllowed(f.FilePath) {
			return yield(f, err)
		}
		s.mu.Lock() // gitleaks yields from several goroutines
		if s.skipped == nil {
			s.skipped = map[string]bool{}
		}
		s.skipped[f.FilePath] = true
		s.mu.Unlock()
		return nil
	})
}

// pathAllowed mirrors gitleaks' path check for "OR" allowlists, which drops
// the change before any rule runs.
func (s *sizeLimited) pathAllowed(path string) bool {
	for _, a := range s.allow {
		if a.MatchCondition != config.AllowlistMatchAnd && a.PathAllowed(path) {
			return true
		}
	}
	return false
}

// skippedPaths returns the skipped paths, sorted.
func (s *sizeLimited) skippedPaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.skipped))
	for p := range s.skipped {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// skippedLargeWarning tells which history paths had changes over the size
// limit, naming at most five. Paths come from the repository, so control
// characters are removed and key-shaped text is hidden.
func skippedLargeWarning(paths []string) string {
	const shown = 5
	names := make([]string, 0, shown)
	for _, p := range paths[:min(len(paths), shown)] {
		p = strings.Map(func(r rune) rune {
			if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
				return -1
			}
			return r
		}, p)
		names = append(names, finding.ScrubNarrow(p))
	}
	list := strings.Join(names, ", ")
	if len(paths) > shown {
		list += fmt.Sprintf(" 외 %d개", len(paths)-shown)
	}
	return fmt.Sprintf("git 기록에서 5MB가 넘는 변경은 점검 시간이 너무 길어 건너뛰었습니다(파일 %d개: %s). 그 변경에만 든 비밀 키는 빠졌을 수 있습니다.", len(paths), list)
}

// errTracking records whether the source handed an error to the detector,
// which gitleaks only logs (e.g. git's "stderr is not empty").
type errTracking struct {
	inner  sources.Source
	failed atomic.Bool
}

func (s *errTracking) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return s.inner.Fragments(ctx, func(f sources.Fragment, err error) error {
		if err != nil {
			s.failed.Store(true)
		}
		return yield(f, err)
	})
}

// Under --untrusted the repository's own settings must not take a file's text out
// of the patches gitleaks reads. --text answers .gitattributes (-diff, binary, a
// diff driver's binary) from any source and core.bigFileThreshold; --no-color
// answers color.*, whose escapes break the secret apart.
const untrustedLogOpts = " --text --no-color"

// untrustedGitConfig answers settings no option covers. log.showRoot=false would
// leave the first commit's patch out.
var untrustedGitConfig = [][2]string{
	{"log.showRoot", "true"},
}

// untrustedGitEnv stops replace refs from swapping commits for clean ones.
var untrustedGitEnv = [][2]string{
	{"GIT_NO_REPLACE_OBJECTS", "1"},
}

// safeGitConfig overrides settings in the scanned repo's .git/config that
// make git run programs. Command-line-level config (GIT_CONFIG_COUNT) beats
// repo config. diff.<driver>.textconv cannot be listed (driver names are
// arbitrary); --no-textconv in gitLogOpts covers it. git log runs no hooks.
var safeGitConfig = [][2]string{
	{"gpg.program", "false"},
	{"gpg.openpgp.program", "false"},
	{"gpg.x509.program", "false"},
	{"gpg.ssh.program", "false"},
	{"log.showSignature", "false"},
	{"core.fsmonitor", "false"},
	{"diff.external", ""},
	{"core.pager", "cat"},
}

// safeGitEnv stops git from reaching any remote: a partial clone's missing
// objects would otherwise be fetched lazily from the promisor remote, which
// runs remote.*.uploadpack, core.sshCommand or an ext:: URL from the scanned
// repo's config. No prompts either.
var safeGitEnv = [][2]string{
	{"GIT_NO_LAZY_FETCH", "1"},
	{"GIT_ALLOW_PROTOCOL", "none"},
	{"GIT_TERMINAL_PROMPT", "0"},
}

// gitEnvMu serialises changes to the process environment.
var gitEnvMu sync.Mutex

// withGitSettings runs fn with config and env added to the process environment
// and restores it afterwards. gitleaks starts its git children (log, cat-file)
// with exec.Command and no way to pass an Env, so the inherited environment is the
// only hook. Existing GIT_CONFIG_COUNT entries are kept: ours are appended after
// them, so ours win.
func withGitSettings(config, env [][2]string, fn func() error) error {
	gitEnvMu.Lock()
	defer gitEnvMu.Unlock()

	base := 0
	if v, ok := os.LookupEnv("GIT_CONFIG_COUNT"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return fmt.Errorf("GIT_CONFIG_COUNT 값이 올바르지 않습니다: %q", v)
		}
		base = n
	}
	set := map[string]string{"GIT_CONFIG_COUNT": strconv.Itoa(base + len(config))}
	for i, kv := range config {
		set[fmt.Sprintf("GIT_CONFIG_KEY_%d", base+i)] = kv[0]
		set[fmt.Sprintf("GIT_CONFIG_VALUE_%d", base+i)] = kv[1]
	}
	for _, kv := range env {
		set[kv[0]] = kv[1]
	}
	type saved struct {
		val string
		ok  bool
	}
	prev := map[string]saved{}
	for k, v := range set {
		old, ok := os.LookupEnv(k)
		prev[k] = saved{old, ok}
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	defer func() {
		for k, p := range prev {
			if p.ok {
				os.Setenv(k, p.val)
			} else {
				os.Unsetenv(k)
			}
		}
	}()
	return fn()
}

// hasGit reports whether root is inside a git repository, which may start in a
// parent folder (monorepo). It only looks at the file system and runs no git.
func hasGit(root string) bool {
	dir, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// testDirs, exampleDirs and docDirs are folder names whose files are
// usually tests, examples or documentation. A key there is more often a
// sample, so it is shown as "의심" with the reason; it is never dropped and its
// severity stays, since a real key can sit in a test folder too.
var (
	testDirs = map[string]bool{
		"test": true, "tests": true, "__tests__": true, "spec": true, "testdata": true,
		"fixtures": true, "__fixtures__": true, "mocks": true, "__mocks__": true,
	}
	exampleDirs = map[string]bool{"example": true, "examples": true, "sample": true, "samples": true, "demo": true, "demos": true}
	docDirs     = map[string]bool{"docs": true, "doc": true}
	docExts     = []string{".md", ".mdx", ".rst", ".adoc"}
	// hashNames are words in a value's name that say it is a hash, not a key.
	hashNames = []string{"hash", "digest", "checksum"}
	// passwordHashPrefixes start the stored forms of argon2, bcrypt, scrypt,
	// PBKDF2 and SHA-crypt password hashes.
	passwordHashPrefixes = []string{"$argon2", "$2a$", "$2b$", "$2y$", "$scrypt", "$pbkdf2", "$5$", "$6$"}
	uuidShape            = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// lowerReason says why a secret finding is shown as "의심", or "" when it is
// not: where the file is, or for generic-api-key what the value looks like.
func lowerReason(loc string, g report.Finding) string {
	parts := strings.Split(strings.ToLower(loc), "/")
	name := parts[len(parts)-1]
	for _, p := range parts[:len(parts)-1] {
		switch {
		case testDirs[p]:
			return "시험 폴더에 있음, 시험용 값인지 확인"
		case exampleDirs[p]:
			return "예제 폴더에 있음, 예시 값인지 확인"
		case docDirs[p] || strings.HasSuffix(p, "-docs") || strings.HasSuffix(p, "_docs"):
			return "문서에 있음, 예시 값인지 확인"
		}
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if strings.HasSuffix(base, "_test") || strings.HasSuffix(base, ".test") || strings.HasSuffix(base, ".spec") ||
		strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".py") {
		return "시험 파일에 있음, 시험용 값인지 확인"
	}
	for _, ext := range docExts {
		if strings.HasSuffix(name, ext) {
			return "문서에 있음, 예시 값인지 확인"
		}
	}
	if g.RuleID != "generic-api-key" {
		return ""
	}
	if uuidShape.MatchString(g.Secret) {
		return "UUID 모양 값, 키인지 확인"
	}
	for _, p := range passwordHashPrefixes {
		if strings.HasPrefix(g.Secret, p) {
			return "비밀번호 해시 모양 값, 키인지 확인"
		}
	}
	// The name is what the match holds before the value.
	before, _, _ := strings.Cut(strings.ToLower(g.Match), strings.ToLower(g.Secret))
	for _, h := range hashNames {
		if strings.Contains(before, h) {
			return "이름으로 보아 해시 값, 키인지 확인"
		}
	}
	return ""
}

const supabasePublishablePrefix = "sb_publishable_"

// isPublicSupabaseKey reports whether secret is a Supabase key meant to be
// public: a publishable key, or a legacy JWT whose payload role is "anon".
// service_role, malformed and unknown JWTs are not public.
func isPublicSupabaseKey(secret string) bool {
	if strings.HasPrefix(secret, supabasePublishablePrefix) {
		return true
	}
	parts := strings.Split(secret, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false
	}
	var claims struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	return claims.Role == "anon"
}

// dropPublicSupabaseKeys removes findings whose secret is a public Supabase
// key. Only the secret is checked: the match may hold other keys on the line.
func dropPublicSupabaseKeys(in []report.Finding) []report.Finding {
	out := in[:0:0]
	for _, g := range in {
		if isPublicSupabaseKey(g.Secret) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// decodedNote says how a finding's value was encoded in the file, from the tags
// gitleaks adds when it finds a secret only after decoding.
func decodedNote(tags []string) (note, evidenceTail string) {
	var names []string
	for _, t := range tags {
		kind, ok := strings.CutPrefix(t, "decoded:")
		if !ok {
			continue
		}
		name := decodedNames[kind]
		if name == "" {
			name = "인코딩을"
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", ""
	}
	what := strings.Join(names, ", ")
	return what + " 풀어서 찾음", " (" + what + " 푼 값)"
}

// decodedNames gives each gitleaks encoding name its Korean wording, with the
// object particle the sentence needs.
var decodedNames = map[string]string{
	"base64":  "base64를",
	"hex":     "16진수(hex)를",
	"percent": "URL 인코딩(%)을",
	"unicode": "유니코드 이스케이프(\\u)를",
}
