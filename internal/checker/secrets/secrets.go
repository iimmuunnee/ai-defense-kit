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
	maxFileSize        = 1 << 20 // 1MB
	warnNoGit          = "git 기록이 없어 과거 커밋은 확인하지 못했습니다."
	warnHistoryPartial = "git 기록을 읽지 못해 과거 커밋 일부는 확인하지 못했습니다 (git 오류 또는 빠진 객체)."
	gitLogOpts         = "--full-history --all --diff-filter=tuxdb --no-textconv --no-ext-diff --no-show-signature --relative"
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

	current, err := scanFiles(ctx, root, t.Untrusted)
	if err != nil {
		return checker.Result{}, fmt.Errorf("현재 파일 점검 실패: %w", err)
	}

	var res checker.Result
	var history []report.Finding
	if hasGit(root) {
		var partial bool
		history, partial, err = scanHistory(ctx, root, t.Untrusted)
		if err == nil && partial {
			res.Warnings = append(res.Warnings, warnHistoryPartial)
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

	current = dropPublicSupabaseKeys(current)
	history = dropPublicSupabaseKeys(history)

	explainCur := c.explain("secret-current.md")
	explainHist := c.explain("secret-history.md")

	seen := map[string]bool{}
	curLoc := func(g report.Finding) string { return finding.NormalizePath(root, g.File) }
	var curPos, histPos [][2]int
	for _, g := range current {
		k := g.RuleID + "\x00" + g.Secret
		loc := curLoc(g)
		seen[k] = true
		res.Findings = append(res.Findings, build(g, "secret-current", loc, finding.High, "코드에 비밀 키가 들어 있음", g.Secret, "", explainCur,
			"코드에서 키를 지우고 환경 변수로 옮긴 뒤, 이미 공유된 적이 있다면 키를 폐기하고 새로 발급하세요."))
		curPos = append(curPos, [2]int{g.StartLine, g.StartColumn})
	}
	nCur := len(res.Findings)
	for _, g := range history {
		k := g.RuleID + "\x00" + g.Secret
		if seen[k] {
			continue
		}
		seen[k] = true
		commit := g.Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		res.Findings = append(res.Findings, build(g, "secret-history", filepath.ToSlash(g.File), finding.Medium, "git 기록에 비밀 키가 남아 있음", g.Secret,
			" (커밋 "+commit+")", explainHist,
			"파일을 지워도 기록에 남습니다. 해당 키를 폐기하고 새로 발급하세요."))
		histPos = append(histPos, [2]int{g.StartLine, g.StartColumn})
	}
	numberRepeats(res.Findings[:nCur], curPos)
	numberRepeats(res.Findings[nCur:], histPos)
	return res, nil
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
	evidence := finding.Redact(secret) + evSuffix
	return finding.Finding{
		ID:          id,
		Source:      "secrets",
		Kind:        kind,
		Severity:    sev,
		Confidence:  confidenceFor(loc),
		Location:    loc,
		Line:        g.StartLine,
		Evidence:    evidence,
		Title:       title + " (" + g.RuleID + ")",
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
	return d.DetectSource(ctx, &sources.Files{
		Path:        root,
		Config:      &d.Config,
		Sema:        d.Sema,
		MaxFileSize: maxFileSize,
	})
}

// scanHistory scans git history. partial reports that git wrote an error
// while gitleaks read the log: gitleaks then stops reading and only logs it.
func scanHistory(ctx context.Context, root string, untrusted bool) (out []report.Finding, partial bool, err error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, false, err
	}
	d, err := newDetector("", untrusted)
	if err != nil {
		return nil, false, err
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
		src := &errTracking{inner: &sources.Git{
			Cmd:    cmd,
			Config: &d.Config,
			Sema:   d.Sema,
			Remote: &sources.RemoteInfo{Platform: scm.NoPlatform}, // no links, no remote lookups
		}}
		out, err = d.DetectSource(ctx, src)
		partial = src.failed.Load()
		return err
	})
	return out, partial, err
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

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true,
	"example": true, "examples": true, "fixtures": true,
}

// confidenceFor returns Suspect when any directory in the path looks like
// test or example code.
func confidenceFor(loc string) finding.Confidence {
	parts := strings.Split(loc, "/")
	for _, p := range parts[:len(parts)-1] {
		if testDirs[strings.ToLower(p)] {
			return finding.Suspect
		}
	}
	return finding.Certain
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
