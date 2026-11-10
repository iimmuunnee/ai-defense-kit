package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	aidefensekit "github.com/iimmuunnee/ai-defense-kit"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/autorun"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/cicd"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/deps"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/supabase"
	"github.com/iimmuunnee/ai-defense-kit/internal/kev"
	"github.com/iimmuunnee/ai-defense-kit/internal/rules"
)

const (
	sampleApp = "../../testdata/e2e/sample-app"
	fakeKey   = "K7Q2X9M4" + "T8W3Z6R1P5V0H2J9L7N4B8D3F6G1"
)

// requirementsOSV adds findings attributed to requirements.txt: requests is
// pinned with == in the sample app (kept), fastapi only with >= (dropped).
const requirementsOSV = `{"results":[{"source":{"path":"requirements.txt","type":"lockfile"},"packages":[
{"package":{"name":"requests","version":"2.31.0","ecosystem":"PyPI"},"groups":[{"ids":["GHSA-e2e-reqs-0001"],"aliases":["GHSA-e2e-reqs-0001"],"max_severity":""}],
 "vulnerabilities":[{"id":"GHSA-e2e-reqs-0001","summary":"E2E pinned requests flaw","affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.32.0"}]}]}]}]},
{"package":{"name":"fastapi","version":"0.110.0","ecosystem":"PyPI"},"groups":[{"ids":["GHSA-e2e-reqs-0002"],"aliases":["GHSA-e2e-reqs-0002"],"max_severity":""}],
 "vulnerabilities":[{"id":"GHSA-e2e-reqs-0002","summary":"E2E unpinned fastapi flaw","affected":[{"package":{"ecosystem":"PyPI","name":"fastapi"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.111.0"}]}]}]}]}
]}]}`

// useFakeDeps replaces deps' OSV and KEV calls with stored fixtures.
func useFakeDeps(t *testing.T) {
	t.Helper()
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{
			rules.NewChecker(data),
			supabase.New(data),
			autorun.New(data),
			cicd.New(data),
			secrets.New(data),
			deps.New(data, deps.Options{
				Scan: func(a osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
					b, err := os.ReadFile("../../testdata/osv/results.json")
					if err != nil {
						return models.VulnerabilityResults{}, err
					}
					var r models.VulnerabilityResults
					if err := json.Unmarshal(b, &r); err != nil {
						return r, err
					}
					var req models.VulnerabilityResults
					if err := json.Unmarshal([]byte(requirementsOSV), &req); err != nil {
						return r, err
					}
					r.Results = append(r.Results, req.Results...)
					for i := range r.Results {
						r.Results[i].Source.Path = filepath.Join(a.DirectoryPaths[0], r.Results[i].Source.Path)
					}
					return r, nil
				},
				FetchKEV: func(context.Context) (*kev.Catalog, error) {
					return &kev.Catalog{}, nil
				},
			}),
		}
	}
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanE2E(t *testing.T) {
	useFakeDeps(t)
	tmp := t.TempDir()
	code, _, stderr := runCLI(t, "scan", sampleApp, "--format", "md,json", "--out", tmp, "--fail-on", "high")
	if code != 1 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	md, err := os.ReadFile(filepath.Join(tmp, "adk-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"KR-PAY-001", "KR-PAY-002", "KR-AUTH-001", "SB-001", "SB-002", "SB-003", "SECRET-", "FA-001", "FA-002", "NX-001", "버전을 정확히 고정하지 않은 라이브러리", "lodash@4.17.15", "fastapi, nextjs, supabase", "이 리포트는 법률 자문이 아닙니다."} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if _, err := os.Stat(filepath.Join(tmp, "adk-report.json")); err != nil {
		t.Error(err)
	}
	// "==" pin is kept; ">=" is dropped and named in the warning.
	if !strings.Contains(string(md), "E2E pinned requests flaw") {
		t.Errorf("pinned requests finding missing:\n%s", md)
	}
	if strings.Contains(string(md), "E2E unpinned fastapi flaw") {
		t.Errorf("unpinned fastapi finding should be dropped:\n%s", md)
	}
	var warn string
	for _, l := range strings.Split(string(md), "\n") {
		if strings.Contains(l, "버전을 정확히 고정하지 않은 라이브러리") {
			warn = l
		}
	}
	if !strings.Contains(warn, "uvicorn") || strings.Contains(warn, "requests") {
		t.Errorf("unpinned warning should list uvicorn and not requests: %q", warn)
	}
}

func TestMarkdownNeverContainsRawSecret(t *testing.T) {
	useFakeDeps(t)
	tmp := t.TempDir()
	runCLI(t, "scan", sampleApp, "--format", "md,json", "--out", tmp)
	for _, name := range []string{"adk-report.md", "adk-report.json"} {
		b, err := os.ReadFile(filepath.Join(tmp, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), fakeKey) || strings.Contains(string(b), fakeKey[4:]) {
			t.Errorf("%s contains the raw secret", name)
		}
		if name == "adk-report.md" && !strings.Contains(string(b), "SECRET-") {
			t.Errorf("secret finding missing; test would be vacuous")
		}
	}
}

func TestScanStdoutDefaultMarkdown(t *testing.T) {
	useFakeDeps(t)
	code, out, _ := runCLI(t, "scan", "--fail-on", "none", sampleApp)
	if code != 0 || !strings.HasPrefix(out, "# adk 점검 리포트") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestScanFailedDepsStrict(t *testing.T) {
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{rules.NewChecker(data), failing{}}
	}
	code, out, _ := runCLI(t, "scan", "--fail-on", "none", sampleApp)
	if code != 0 || !strings.Contains(out, "일부 점검을 하지 못했습니다") {
		t.Errorf("code=%d out=%s", code, out)
	}
	if code, _, _ := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--strict"); code != 2 {
		t.Errorf("strict: code=%d", code)
	}
}

type failing struct{}

func (failing) Name() string { return "deps" }
func (failing) Run(context.Context, checker.Target) (checker.Result, error) {
	return checker.Result{}, os.ErrClosed
}

func TestScanMissingDirExits2(t *testing.T) {
	code, _, stderr := runCLI(t, "scan", filepath.Join(t.TempDir(), "nope"))
	if code != 2 || !strings.Contains(stderr, "찾을 수 없습니다") {
		t.Errorf("code=%d stderr=%s", code, stderr)
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	cases := [][]string{
		{},
		{"bogus"},
		{"scan"},
		{"scan", sampleApp, "--format", "html"},
		{"scan", sampleApp, "--format", "md,json"},
		{"scan", sampleApp, "--fail-on", "info"},
		{"scan", sampleApp, "--fail-on", "bogus"},
		{"scan", sampleApp, "--nope"},
		{"scan", sampleApp, "--rules-dir", filepath.Join(t.TempDir(), "nope")},
	}
	for _, args := range cases {
		code, _, stderr := runCLI(t, args...)
		if code != 2 || stderr == "" {
			t.Errorf("%v: code=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestScanHonorsIgnore(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)

	var rep struct {
		Findings []struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
		}
	}
	tmp := t.TempDir()
	if code, _, se := runCLI(t, "scan", "--fail-on", "none", app, "--format", "json,md", "--out", tmp); code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	var fp string
	for _, f := range rep.Findings {
		if f.ID == "KR-PAY-002" {
			fp = f.Fingerprint
		}
	}
	if fp == "" {
		t.Fatal("KR-PAY-002 finding or fingerprint missing")
	}
	md, _ := os.ReadFile(filepath.Join(tmp, "adk-report.md"))
	if !strings.Contains(string(md), "지문: "+fp+" (무시하려면 .adkignore에 추가)") {
		t.Errorf("markdown lacks fingerprint line:\n%s", md)
	}

	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte("# 테스트\n"+fp+" # 오탐\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// --fail-on none so exit stays 0; check content
	code, out, se := runCLI(t, "scan", app, "--fail-on", "none")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	if strings.Contains(out, "KR-PAY-002") {
		t.Errorf("ignored finding still reported:\n%s", out)
	}
	if !strings.Contains(out, "무시함: 1개") {
		t.Errorf("missing ignored count:\n%s", out)
	}
	if !strings.Contains(out, "SECRET-") {
		t.Errorf("other findings should remain")
	}
}

func TestIgnoredFindingsDoNotFailBuild(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	// ignore everything: collect all fingerprints from a json run. The file is
	// there from the start because it is itself reported (AR-006).
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if code, _, se := runCLI(t, "scan", app, "--format", "json", "--out", tmp, "--fail-on", "low"); code != 1 {
		t.Fatalf("baseline exit %d, want 1 (findings must fail the build before ignoring): %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
		}
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("baseline has no findings; test would be vacuous")
	}
	var lines []string
	for _, f := range rep.Findings {
		lines = append(lines, f.Fingerprint)
	}
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, se := runCLI(t, "scan", app, "--fail-on", "low"); code != 0 {
		t.Errorf("exit %d: %s", code, se)
	}
}

func TestUnreadableIgnoreExits2(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	if err := os.Mkdir(filepath.Join(app, ".adkignore"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, se := runCLI(t, "scan", app)
	if code != 2 || !strings.Contains(se, ".adkignore") {
		t.Errorf("code=%d stderr=%s", code, se)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBrokenRulesFileExits2(t *testing.T) {
	useFakeDeps(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := "title: t\nseverity: high\nmatch:\n  files: [\"**/*.py\"]\n  has_any: [\"x\"]\n" // no id
	if err := os.WriteFile(filepath.Join(dir, "rules", "bad.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "scan", sampleApp, "--rules-dir", dir)
	if code != 2 || !strings.Contains(stderr, "규칙 파일") {
		t.Errorf("code=%d stderr=%s", code, stderr)
	}
}

func TestFailedCheckAlwaysWarnsOnStderr(t *testing.T) {
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{rules.NewChecker(data), failing{}}
	}
	for _, args := range [][]string{
		{"scan", sampleApp, "--format", "json"},
		{"scan", sampleApp, "--out", t.TempDir()},
		{"scan", sampleApp},
	} {
		_, _, stderr := runCLI(t, args...)
		if !strings.Contains(stderr, "일부 점검을 하지 못했습니다") || !strings.Contains(stderr, "deps") ||
			!strings.Contains(stderr, os.ErrClosed.Error()) {
			t.Errorf("%v: stderr lacks failed-check warning: %q", args, stderr)
		}
	}
	// warnings of ok checks mean incomplete coverage too: shown in the block
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{fixed{"rules", nil}, fixed{"secrets", []string{"git 기록이 없어 과거 커밋은 확인하지 못했습니다."}}}
	}
	_, _, stderr := runCLI(t, "scan", sampleApp, "--format", "json")
	if !strings.Contains(stderr, "일부 점검을 하지 못했습니다") || !strings.Contains(stderr, "secrets: git 기록이 없어") {
		t.Errorf("ok-check warning missing on stderr: %q", stderr)
	}
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{fixed{"rules", nil}}
	}
	if _, _, stderr := runCLI(t, "scan", sampleApp, "--format", "json"); strings.Contains(stderr, "일부 점검을 하지 못했습니다") {
		t.Errorf("warning printed although every check ran cleanly: %q", stderr)
	}
}

type fixed struct {
	name  string
	warns []string
}

func (f fixed) Name() string { return f.name }
func (f fixed) Run(context.Context, checker.Target) (checker.Result, error) {
	return checker.Result{Warnings: f.warns}, nil
}

func TestSymlinkedTargetScansEverything(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(app, link); err != nil {
		t.Skip("symlinks unsupported")
	}
	code, out, se := runCLI(t, "scan", link, "--format", "json", "--fail-on", "none")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Location string `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range rep.Findings {
		got[f.ID[:min(len(f.ID), 7)]] = f.Location
	}
	if got["SECRET-"] != "app/config.py" || got["KR-PAY-"] != "app/webhook.py" {
		t.Errorf("findings via symlink = %+v", rep.Findings)
	}
	var deps bool
	for _, f := range rep.Findings {
		deps = deps || f.Location == "package-lock.json"
	}
	if !deps {
		t.Errorf("deps findings missing via symlink: %+v", rep.Findings)
	}
}

func TestHelpExits0(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}, {"scan", "-h"}, {"scan", "--help"}} {
		code, out, _ := runCLI(t, args...)
		if code != 0 || !strings.Contains(out, "사용법") {
			t.Errorf("%v: code=%d out=%q", args, code, out)
		}
	}
}

func TestCancelledScanExits2(t *testing.T) {
	useFakeDeps(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Ctrl-C
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"scan", sampleApp}, &out, &errb); code != 2 {
		t.Errorf("code=%d stderr=%s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "사용자가 점검을 중단했습니다.") || out.Len() != 0 {
		t.Errorf("stderr=%q stdout=%q", errb.String(), out.String())
	}
}

func TestDefaultCheckersIncludeSupabase(t *testing.T) {
	var names []string
	for _, c := range defaultCheckers(aidefensekit.Data, scanOptions{}) {
		names = append(names, c.Name())
	}
	if got := strings.Join(names, ","); !strings.HasPrefix(got, "rules,supabase,") {
		t.Fatalf("checkers = %s", got)
	}
}

func TestScanFindsSupabaseTableWithoutRLS(t *testing.T) {
	useFakeDeps(t)
	tmp := t.TempDir()
	code, _, stderr := runCLI(t, "scan", "--fail-on", "none", "../../testdata/supabase/vulnerable", "--format", "md", "--out", tmp, "--offline")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	md, err := os.ReadFile(filepath.Join(tmp, "adk-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "public.profiles") || !strings.Contains(string(md), "SB-001") {
		t.Errorf("report lacks SB-001 finding:\n%s", md)
	}
}

func TestScanAttachesMappings(t *testing.T) {
	useFakeDeps(t)
	tmp := t.TempDir()
	if code, _, se := runCLI(t, "scan", sampleApp, "--format", "json", "--out", tmp); code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Mappings []struct {
				ID           string `json:"id"`
				ReviewStatus string `json:"review_status"`
			} `json:"mappings"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.ID != "KR-PAY-002" {
			continue
		}
		found = true
		if len(f.Mappings) == 0 || f.Mappings[0].ID != "ISMSP-2.10.4" || f.Mappings[0].ReviewStatus == "" {
			t.Errorf("mappings = %+v", f.Mappings)
		}
	}
	if !found {
		t.Fatal("KR-PAY-002 finding missing")
	}
}

const mappedRule = "id: T-MAP\ntitle: t\nseverity: high\nmatch:\n  files: [\"**/*.py\"]\n  has_any: [\"portone\"]\nmappings: [ISMSP-2.10.4]\n"

func rulesDirWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScanRulesDirWithoutMappings(t *testing.T) {
	useFakeDeps(t)
	app := t.TempDir()
	if err := os.WriteFile(filepath.Join(app, "x.py"), []byte("portone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := rulesDirWith(t, map[string]string{"rules/t.yaml": mappedRule})
	code, out, se := runCLI(t, "scan", app, "--rules-dir", dir, "--format", "json")
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	if !strings.Contains(out, `"review_status": "draft"`) && !strings.Contains(out, `"review_status":"draft"`) {
		t.Errorf("draft status missing:\n%s", out)
	}
	if !strings.Contains(se, "경고") || !strings.Contains(se, "ISMSP-2.10.4") {
		t.Errorf("stderr lacks mapping warning: %q", se)
	}
}

func TestScanBadMappingFile(t *testing.T) {
	useFakeDeps(t)
	bad := "id: ISMSP-9.9.9\nname: x\nsource_url: https://example.com/\nreview:\n  status: draft\n"
	dir := rulesDirWith(t, map[string]string{"rules/t.yaml": mappedRule, "mappings/isms-p/X.yaml": bad})
	code, _, se := runCLI(t, "scan", sampleApp, "--rules-dir", dir)
	if code != 2 || !strings.Contains(se, "국내 기준 파일을 불러오지 못했습니다") {
		t.Errorf("code=%d stderr=%s", code, se)
	}
}

func TestDefaultCheckersIncludeAutorun(t *testing.T) {
	found := false
	for _, c := range defaultCheckers(aidefensekit.Data, scanOptions{}) {
		if c.Name() == "autorun" {
			found = true
		}
	}
	if !found {
		t.Fatal("autorun checker missing from defaultCheckers")
	}
}

func TestDefaultCheckersIncludeCicd(t *testing.T) {
	found := false
	for _, c := range defaultCheckers(aidefensekit.Data, scanOptions{}) {
		if c.Name() == "cicd" {
			found = true
		}
	}
	if !found {
		t.Fatal("cicd checker missing from defaultCheckers")
	}
}

// The CI checker runs in a real scan: findings from the example repository come
// out under their own numbers and a repository without workflows gets none.
func TestScanIncludesCicd(t *testing.T) {
	useFakeDeps(t)
	tmp := t.TempDir()
	if code, _, se := runCLI(t, "scan", "../../testdata/cicd/risky", "--format", "json", "--out", tmp, "--offline"); code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
		Findings []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	ran := false
	for _, c := range rep.Checks {
		if c.Name == "cicd" && c.Status == "ok" {
			ran = true
		}
	}
	if !ran {
		t.Errorf("checks = %+v", rep.Checks)
	}
	count := map[string]int{}
	for _, f := range rep.Findings {
		if f.Source == "cicd" {
			count[f.ID]++
		}
	}
	if count["CI-001"] != 2 || count["CI-002"] != 3 || count["CI-003"] != 1 || count["CI-004"] != 1 {
		t.Errorf("cicd findings = %v", count)
	}

	// no .github/workflows: the scan of the sample app has no cicd result
	tmp2 := t.TempDir()
	if code, _, se := runCLI(t, "scan", sampleApp, "--format", "json", "--out", tmp2, "--offline"); code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, _ = os.ReadFile(filepath.Join(tmp2, "adk-report.json"))
	if strings.Contains(string(b), `"source": "cicd"`) || strings.Contains(string(b), `"source":"cicd"`) {
		t.Error("sample app has no workflows but got a cicd finding")
	}
}

func TestScanIncludesAutorun(t *testing.T) {
	useFakeDeps(t)
	app := t.TempDir()
	if err := os.MkdirAll(filepath.Join(app, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	tasks := `{"tasks":[{"label":"dev","command":"node","args":["x.js"],"runOptions":{"runOn":"folderOpen"}}]}`
	if err := os.WriteFile(filepath.Join(app, ".vscode", "tasks.json"), []byte(tasks), 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if code, _, se := runCLI(t, "scan", app, "--format", "json", "--out", tmp, "--offline"); code != 0 && code != 1 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"checks"`
		Findings []struct {
			ID       string `json:"id"`
			Source   string `json:"source"`
			Evidence string `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	ran := false
	for _, c := range rep.Checks {
		if c.Name == "autorun" && c.Status == "ok" {
			ran = true
		}
	}
	if !ran {
		t.Errorf("checks = %+v", rep.Checks)
	}
	hit := false
	for _, f := range rep.Findings {
		if f.ID == "AR-001" && f.Source == "autorun" && f.Evidence == `dev: {"command":"node","args":["x.js"],"label":"dev","runOptions":{"runOn":"folderOpen"}}` {
			hit = true
		}
	}
	if !hit {
		t.Errorf("findings = %+v", rep.Findings)
	}
}

const fakeAssignment = "../../testdata/untrusted/fake-assignment"

// scanFakeAssignment runs the real checkers offline (no network) and returns
// the JSON report's findings plus stderr.
func scanFakeAssignment(t *testing.T, app string, extra ...string) ([]struct{ ID, Evidence string }, string) {
	t.Helper()
	tmp := t.TempDir()
	args := append([]string{"scan", app, "--format", "json", "--out", tmp, "--offline"}, extra...)
	code, _, se := runCLI(t, args...)
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Evidence string `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	var out []struct{ ID, Evidence string }
	for _, f := range rep.Findings {
		out = append(out, struct{ ID, Evidence string }{f.ID, f.Evidence})
	}
	return out, se
}

// Without its .adkignore the example shows every AR number.
func TestScanFakeAssignment(t *testing.T) {
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, fakeAssignment, app)
	if err := os.Remove(filepath.Join(app, ".adkignore")); err != nil {
		t.Fatal(err)
	}
	// The .adkignore is the AR-006 trigger; put back one that hides nothing.
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte("0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _ := scanFakeAssignment(t, app)
	got := map[string]string{}
	for _, f := range fs {
		got[f.ID] = f.Evidence
	}
	for _, id := range []string{"AR-001", "AR-002", "AR-003", "AR-004", "AR-005", "AR-006"} {
		ev, ok := got[id]
		if !ok {
			t.Errorf("%s missing: %+v", id, fs)
			continue
		}
		if id != "AR-006" && !strings.Contains(ev, "echo adk-test") && !strings.Contains(ev, `"echo"`) {
			t.Errorf("%s evidence does not show the command: %q", id, ev)
		}
	}
	for _, f := range fs {
		if strings.HasPrefix(f.ID, "MAL-") {
			t.Errorf("example holds no malicious package: %+v", f)
		}
	}
}

// The example's own .adkignore hides AR-001: the default scan hides it and
// warns, --untrusted shows it and warns of nothing.
func TestScanFakeAssignmentUntrusted(t *testing.T) {
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, fakeAssignment, app)

	fs, se := scanFakeAssignment(t, app)
	for _, f := range fs {
		if f.ID == "AR-001" {
			t.Errorf("default scan should hide AR-001: %+v", f)
		}
	}
	if !strings.Contains(se, "숨겼습니다") {
		t.Errorf("default scan should warn about the hidden finding:\n%s", se)
	}

	fs, se = scanFakeAssignment(t, app, "--untrusted")
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.ID] = true
	}
	for _, id := range []string{"AR-001", "AR-002", "AR-003", "AR-004", "AR-005", "AR-006"} {
		if !ids[id] {
			t.Errorf("--untrusted lacks %s: %+v", id, fs)
		}
	}
	if strings.Contains(se, "숨겼습니다") {
		t.Errorf("--untrusted hides nothing:\n%s", se)
	}
}

// A workflow the scan could not read is a result that counts for --fail-on,
// not only a warning.
func TestScanUnreadableWorkflowCountsForFailOn(t *testing.T) {
	useFakeDeps(t)
	mk := func(t *testing.T) (string, string) {
		app := t.TempDir()
		dir := filepath.Join(app, ".github", "workflows")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return app, dir
	}
	check := func(t *testing.T, app string) {
		t.Helper()
		tmp := t.TempDir()
		code, _, se := runCLI(t, "scan", app, "--format", "json", "--out", tmp, "--offline", "--fail-on", "medium")
		if code != 1 {
			t.Fatalf("exit %d, want 1: %s", code, se)
		}
		b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"id": "CI-005"`) {
			t.Errorf("no CI-005 in report:\n%s", b)
		}
	}
	t.Run("oversized file", func(t *testing.T) {
		app, dir := mk(t)
		big := "name: x\n# " + strings.Repeat("x", 1<<20) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "big.yml"), []byte(big), 0o644); err != nil {
			t.Fatal(err)
		}
		check(t, app)
	})
	t.Run("symlinked file", func(t *testing.T) {
		app, dir := mk(t)
		target := filepath.Join(t.TempDir(), "w.yml")
		os.WriteFile(target, []byte("name: x\n"), 0o644)
		if err := os.Symlink(target, filepath.Join(dir, "link.yml")); err != nil {
			t.Skipf("symlink not available: %v", err)
		}
		check(t, app)
	})
	t.Run("symlinked folder", func(t *testing.T) {
		app := t.TempDir()
		os.MkdirAll(filepath.Join(app, ".github"), 0o755)
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(app, ".github", "workflows")); err != nil {
			t.Skipf("symlink not available: %v", err)
		}
		check(t, app)
	})
}
