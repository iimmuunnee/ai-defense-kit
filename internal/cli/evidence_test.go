package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
	"github.com/iimmuunnee/ai-defense-kit/internal/rules"
)

func TestScanNoEvidenceWithoutOut(t *testing.T) {
	useFakeDeps(t)
	app, err := filepath.Abs(sampleApp)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	t.Chdir(cwd)
	code, out, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "sarif")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	validateSARIF(t, []byte(out))
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Errorf("stdout is not SARIF:\n%s", out)
	}
	if ents, _ := os.ReadDir(cwd); len(ents) != 0 {
		t.Errorf("files written to the working folder: %v", ents)
	}
	if strings.Contains(se, "증적") {
		t.Errorf("stderr mentions evidence: %s", se)
	}
}

func TestScanEvidenceOnFindingsExit1(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	code, _, se := runCLI(t, "scan", sampleApp, "--fail-on", "low", "--format", "json", "--out", out)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, se)
	}
	ev, _ := readEvidence(t, out)
	if len(ev.Findings) == 0 {
		t.Error("evidence has no findings")
	}
}

// pathErr fails with a message that holds the absolute scan path.
type pathErr struct{}

func (pathErr) Name() string { return "extra" }
func (pathErr) Run(_ context.Context, t checker.Target) (checker.Result, error) {
	return checker.Result{}, fmt.Errorf("읽지 못했습니다: %s", t.Root)
}

func TestScanEvidenceNoAbsolutePathOrKey(t *testing.T) {
	useFakeDeps(t)
	inner := defaultCheckers
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return append(inner(data, opt), pathErr{})
	}
	app := filepath.Join(t.TempDir(), "myapp")
	copyTree(t, sampleApp, app)
	out := t.TempDir()
	code, _, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "sarif,json", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	if !strings.Contains(se, "myapp") {
		t.Fatalf("test is vacuous: the terminal warning should keep the path: %s", se)
	}
	for _, n := range []string{"adk-evidence.json", "adk-report.sarif"} {
		b, err := os.ReadFile(filepath.Join(out, n))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{app, filepath.ToSlash(app), strings.ReplaceAll(app, `\`, `\\`), fakeKey, fakeKey[4:]} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q", n, bad)
			}
		}
		if !strings.Contains(s, "읽지 못했습니다") {
			t.Errorf("%s lacks the failed-check text; test would be vacuous", n)
		}
	}
}

func TestScanEvidenceIgnored(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	base := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "json", "--out", base); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	ev0, _ := readEvidence(t, base)
	var fp string
	for _, f := range ev0.Findings {
		if f.ID == "KR-PAY-002" {
			fp = f.Fingerprint
		}
	}
	if fp == "" {
		t.Fatal("KR-PAY-002 missing")
	}
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte(fp+" # 오탐\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "json,sarif", "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	ev, _ := readEvidence(t, out)
	if len(ev.Ignored) != 1 || ev.Ignored[0].Fingerprint != fp {
		t.Errorf("ignored = %+v", ev.Ignored)
	}
	for _, f := range ev.Findings {
		if f.Fingerprint == fp {
			t.Error("ignored finding still in findings")
		}
	}
	sarif, _ := os.ReadFile(filepath.Join(out, "adk-report.sarif"))
	if strings.Contains(string(sarif), fp) {
		t.Error("ignored finding in SARIF")
	}
	var rep struct {
		Ignored int `json:"ignored"`
	}
	b, _ := os.ReadFile(filepath.Join(out, "adk-report.json"))
	if err := json.Unmarshal(b, &rep); err != nil || rep.Ignored != 1 {
		t.Errorf("adk-report.json ignored = %d (%v), want the count 1", rep.Ignored, err)
	}
}

func TestScanStrictFailureStillWrites(t *testing.T) {
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{rules.NewChecker(data), failing{}}
	}
	out := t.TempDir()
	code, _, se := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--strict", "--format", "md,sarif", "--out", out)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %s", code, se)
	}
	ev, _ := readEvidence(t, out)
	failed := false
	for _, c := range ev.Checks {
		if c.Name == "deps" && c.Status == "failed" {
			failed = true
		}
	}
	if !failed {
		t.Errorf("checks = %+v", ev.Checks)
	}
	b, _ := os.ReadFile(filepath.Join(out, "adk-report.sarif"))
	validateSARIF(t, b)
	var log struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Invocations) != 1 || log.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Errorf("executionSuccessful should be false: %s", b)
	}
}

func TestScanNoCheckerRanNoEvidence(t *testing.T) {
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{failing{}}
	}
	out := t.TempDir()
	code, _, _ := runCLI(t, "scan", sampleApp, "--format", "md", "--out", out)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		t.Errorf("files written: %v", ents)
	}
}

func TestScanEvidenceWriteFailureExit2(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "adk-evidence.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, se := runCLI(t, "scan", sampleApp, "--format", "md", "--out", out)
	if code != 2 || !strings.Contains(se, "adk-evidence.json") {
		t.Errorf("code=%d stderr=%s", code, se)
	}
}

func TestScanStaleReportNotListed(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "adk-report.sarif"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--format", "md", "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	ev, _ := readEvidence(t, out)
	if len(ev.Reports) != 1 || ev.Reports[0].File != "adk-report.md" {
		t.Errorf("reports = %+v", ev.Reports)
	}
}

func cleanSampleRepo(t *testing.T) string {
	t.Helper()
	repo := newGitRepo(t)
	copyTree(t, sampleApp, repo)
	commitAll(t, repo)
	return repo
}

func TestScanOutInsideRepoDirty(t *testing.T) {
	useFakeDeps(t)
	repo := cleanSampleRepo(t)
	out := filepath.Join(repo, "out")
	for i, want := range []string{"no", "yes"} {
		if code, _, se := runCLI(t, "scan", "--fail-on", "none", repo, "--format", "md", "--out", out); code != 0 {
			t.Fatalf("run %d: exit %d: %s", i+1, code, se)
		}
		ev, _ := readEvidence(t, out)
		if ev.Git.Dirty != want {
			t.Errorf("run %d: dirty = %q, want %q", i+1, ev.Git.Dirty, want)
		}
		if ev.Git.Commit == "" {
			t.Errorf("run %d: commit empty", i+1)
		}
	}

	// --out . on a clean repo: this run's reports are not counted ...
	repo = cleanSampleRepo(t)
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", repo, "--format", "md", "--out", repo); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	if ev, _ := readEvidence(t, repo); ev.Git.Dirty != "no" {
		t.Errorf("--out . clean: dirty = %q, want no", ev.Git.Dirty)
	}
	// ... but a real change still is.
	repo = cleanSampleRepo(t)
	writeT(t, filepath.Join(repo, "app", "config.py"), "changed = 1\n")
	if code, _, se := runCLI(t, "scan", repo, "--format", "md", "--out", repo); code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, se)
	}
	if ev, _ := readEvidence(t, repo); ev.Git.Dirty != "yes" {
		t.Errorf("--out . changed: dirty = %q, want yes", ev.Git.Dirty)
	}
}

func TestScanSubfolderPrefix(t *testing.T) {
	useFakeDeps(t)
	repo := newGitRepo(t)
	copyTree(t, sampleApp, filepath.Join(repo, "apps", "web"))
	commitAll(t, repo)
	out := t.TempDir()
	code, _, se := runCLI(t, "scan", "--fail-on", "none", filepath.Join(repo, "apps", "web"), "--format", "sarif,json", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, _ := os.ReadFile(filepath.Join(out, "adk-report.sarif"))
	validateSARIF(t, b)
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range log.Runs[0].Results {
		for _, l := range r.Locations {
			n++
			if u := l.PhysicalLocation.ArtifactLocation.URI; !strings.HasPrefix(u, "apps/web/") {
				t.Errorf("uri %q lacks the repository prefix", u)
			}
		}
	}
	if n == 0 {
		t.Fatal("no located results; test would be vacuous")
	}
	ev, _ := readEvidence(t, out)
	if ev.Target != "web" {
		t.Errorf("target = %q", ev.Target)
	}
	for _, f := range ev.Findings {
		if strings.HasPrefix(f.Location, "apps/") {
			t.Errorf("evidence location %q must stay relative to the scanned folder", f.Location)
		}
	}
}

func TestScanRulesDirOrigin(t *testing.T) {
	useFakeDeps(t)
	base := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--format", "md", "--out", base); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, _ := readEvidence(t, base)
	if b.Data.Rules == nil || b.Data.Rules.Origin != "builtin" || b.Data.Mappings.Origin != "builtin" {
		t.Fatalf("default data: %+v", b.Data)
	}

	dir := rulesDirWith(t, map[string]string{"rules/t.yaml": mappedRule})
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", sampleApp, "--rules-dir", dir, "--format", "md", "--out", out); code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	c, _ := readEvidence(t, out)
	if c.Data.Rules == nil || c.Data.Rules.Origin != "custom" || c.Data.Mappings.Origin != "custom" {
		t.Fatalf("custom data: %+v", c.Data)
	}
	if c.Data.Rules.SHA256 == b.Data.Rules.SHA256 || c.Data.Mappings.SHA256 == b.Data.Mappings.SHA256 {
		t.Error("custom hashes equal the built-in hashes")
	}
	if c.Data.Rules.Count != 1 {
		t.Errorf("custom rule count = %d", c.Data.Rules.Count)
	}
}

func TestScanEvidenceData(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--format", "md", "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	ev, _ := readEvidence(t, out)
	rs, err := rules.Load(aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := mapping.Load(aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Data.Rules == nil || ev.Data.Rules.Count != len(rs) {
		t.Errorf("rules = %+v, want count %d", ev.Data.Rules, len(rs))
	}
	if ev.Data.Mappings.Count != cat.Len() {
		t.Errorf("mappings count = %d, want %d", ev.Data.Mappings.Count, cat.Len())
	}
	wantRules, _ := report.HashTree(aidefensekit.Data, "rules")
	wantMaps, _ := report.HashTree(aidefensekit.Data, "mappings")
	if ev.Data.Rules.SHA256 != wantRules || ev.Data.Mappings.SHA256 != wantMaps {
		t.Error("hashes differ from report.HashTree of the built-in data")
	}
	items := cat.Items()
	if len(ev.Data.Mappings.Items) != len(items) || len(items) == 0 {
		t.Fatalf("items: %d vs %d", len(ev.Data.Mappings.Items), len(items))
	}
	for i, it := range items {
		got := ev.Data.Mappings.Items[i]
		status := it.Review.Status
		if status == "" {
			status = "draft"
		}
		if got.ID != it.ID || got.SourceVersion != it.SourceVersion || got.ReviewStatus != status {
			t.Errorf("item %d: %+v vs %+v", i, got, it)
		}
	}
}

func TestAssetsWritesEvidence(t *testing.T) {
	sampleCrtsh(t)
	dir := t.TempDir()
	t.Chdir(dir)
	known := filepath.Join(dir, "subdir", "known.txt")
	writeT(t, known, "example.test\n")
	out := filepath.Join(dir, "out")
	code, _, se := runCLI(t, "assets", "example.test", "--known", known, "--format", "md,json", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	ev, raw := readEvidence(t, out)
	if ev.Kind != "assets" || ev.Target != "example.test" {
		t.Errorf("header: %+v", ev)
	}
	if ev.Data.Rules != nil {
		t.Errorf("assets must not record rules: %+v", ev.Data.Rules)
	}
	if ev.Data.Mappings.Count == 0 {
		t.Error("mappings not recorded")
	}
	if ev.KnownList != "known.txt" || strings.Contains(string(raw), "subdir") {
		t.Errorf("known_list = %q; the path must not leak", ev.KnownList)
	}
	if ev.Git.Dirty != "unknown" || ev.Git.Commit != "" {
		t.Errorf("git = %+v", ev.Git)
	}
	if len(ev.Reports) != 2 {
		t.Fatalf("reports = %+v", ev.Reports)
	}
	for _, r := range ev.Reports {
		if r.SHA256 != fileSHA(t, filepath.Join(out, r.File)) {
			t.Errorf("%s hash mismatch", r.File)
		}
	}
	if strings.Contains(string(raw), dir) || strings.Contains(string(raw), filepath.ToSlash(dir)) {
		t.Error("evidence leaks the working path")
	}
}

func TestAssetsRejectsSARIF(t *testing.T) {
	f := sampleCrtsh(t)
	t.Chdir(t.TempDir())
	for _, fmtArg := range []string{"sarif", "md,sarif"} {
		code, out, se := runCLI(t, "assets", "example.test", "--format", fmtArg, "--out", t.TempDir())
		if code != 2 || out != "" {
			t.Errorf("%s: code=%d out=%q", fmtArg, code, out)
		}
		if !strings.Contains(se, "SARIF로 낼 수 없습니다") || !strings.Contains(se, "--format md,json") {
			t.Errorf("%s: stderr = %q", fmtArg, se)
		}
	}
	if f.requests() != 0 {
		t.Errorf("requests = %d, want 0", f.requests())
	}
}

func TestFormatErrorMentionsSARIF(t *testing.T) {
	code, _, se := runCLI(t, "scan", sampleApp, "--format", "html")
	if code != 2 || !strings.Contains(se, "(md, json, sarif만 가능)") {
		t.Errorf("code=%d stderr=%q", code, se)
	}
	if !strings.Contains(usageText, "--format md,json,sarif") {
		t.Errorf("usage lacks sarif: %s", usageText)
	}
}

func TestScanGitFieldsIgnoreInheritedGitEnv(t *testing.T) {
	useFakeDeps(t)
	repo := cleanSampleRepo(t)
	other := newGitRepo(t)
	writeT(t, filepath.Join(other, "o.txt"), "other\n")
	commitAll(t, other)
	want := strings.TrimSpace(runGitT(t, repo, "rev-parse", "HEAD"))
	otherHead := strings.TrimSpace(runGitT(t, other, "rev-parse", "HEAD"))
	if want == otherHead {
		t.Fatal("test is vacuous: both repositories share a HEAD")
	}
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", repo, "--format", "md", "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	ev, _ := readEvidence(t, out)
	if ev.Git.Commit != want {
		t.Errorf("commit = %q, want the scanned repository's HEAD %q", ev.Git.Commit, want)
	}
	if ev.Git.Dirty != "no" {
		t.Errorf("dirty = %q, want no", ev.Git.Dirty)
	}
}
