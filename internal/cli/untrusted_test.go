package cli

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const hideWarning = "결과 1개를 숨겼습니다. 받은 코드라면 --untrusted로 다시 점검하세요."

// appWithHiddenFinding is a copy of the sample app whose .adkignore hides one finding.
func appWithHiddenFinding(t *testing.T) (app, fingerprint string) {
	t.Helper()
	app = filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	dir := t.TempDir()
	if code, _, se := runCLI(t, "scan", app, "--format", "json", "--out", dir); code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	var doc struct {
		Findings []struct{ ID, Fingerprint string }
	}
	b, err := os.ReadFile(filepath.Join(dir, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if f.ID == "KR-PAY-002" {
			fingerprint = f.Fingerprint
		}
	}
	if fingerprint == "" {
		t.Fatal("sample app has no KR-PAY-002 finding")
	}
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte(fingerprint+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return app, fingerprint
}

func evidenceMap(t *testing.T, dir string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "adk-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestUntrustedIgnoresAdkignore(t *testing.T) {
	useFakeDeps(t)
	app, fp := appWithHiddenFinding(t)

	dir := t.TempDir()
	if code, _, se := runCLI(t, "scan", app, "--format", "md", "--out", dir); code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	md, err := os.ReadFile(filepath.Join(dir, "adk-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(md), fp) {
		t.Errorf("without --untrusted the finding should be hidden")
	}
	ev := evidenceMap(t, dir)
	if ev["untrusted"] != false || len(ev["ignored"].([]any)) != 1 {
		t.Errorf("evidence: untrusted=%v ignored=%v", ev["untrusted"], ev["ignored"])
	}

	dir = t.TempDir()
	code, _, se := runCLI(t, "scan", app, "--untrusted", "--format", "md", "--out", dir)
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	md, err = os.ReadFile(filepath.Join(dir, "adk-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), fp) {
		t.Errorf("--untrusted should show the finding")
	}
	if strings.Contains(string(md), "무시함") || strings.Contains(string(md), "숨겼습니다") || strings.Contains(se, "숨겼습니다") {
		t.Errorf("--untrusted hides nothing:\n%s\n%s", md, se)
	}
	ev = evidenceMap(t, dir)
	if ev["untrusted"] != true || len(ev["ignored"].([]any)) != 0 {
		t.Errorf("evidence: untrusted=%v ignored=%v", ev["untrusted"], ev["ignored"])
	}
}

// The file is not opened at all, so a broken one cannot stop the scan.
func TestUntrustedDoesNotReadAdkignore(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	if err := os.Mkdir(filepath.Join(app, ".adkignore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, se := runCLI(t, "scan", app); code != 2 {
		t.Errorf("without --untrusted: code=%d stderr=%s", code, se)
	}
	if code, _, se := runCLI(t, "scan", app, "--untrusted"); code == 2 {
		t.Errorf("--untrusted: stderr=%s", se)
	}
}

func TestAdkignoreHidingWarns(t *testing.T) {
	useFakeDeps(t)
	app, _ := appWithHiddenFinding(t)
	code, out, se := runCLI(t, "scan", app)
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	want := ".adkignore가 " + hideWarning
	if !strings.Contains(se, want) {
		t.Errorf("stderr lacks warning:\n%s", se)
	}
	if !strings.HasPrefix(out, "# adk 점검 리포트\n\n> ⚠️ "+want+"\n") {
		t.Errorf("markdown does not open with the warning:\n%.300s", out)
	}

	_, out, se = runCLI(t, "scan", app, "--format", "json")
	if strings.Contains(out, "숨겼습니다") || !strings.Contains(se, want) {
		t.Errorf("JSON must not change, stderr must warn:\n%.300s\n%s", out, se)
	}

	if err := os.Remove(filepath.Join(app, ".adkignore")); err != nil {
		t.Fatal(err)
	}
	_, out, se = runCLI(t, "scan", app)
	if strings.Contains(out, "숨겼습니다") || strings.Contains(se, "숨겼습니다") {
		t.Errorf("nothing was hidden:\n%.300s\n%s", out, se)
	}
}

// A .adkignore that hides nothing is reported by AR-006, not by this warning.
func TestAdkignoreHidingNothingDoesNotWarn(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte("0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, se := runCLI(t, "scan", app)
	if strings.Contains(out, "숨겼습니다") || strings.Contains(se, "숨겼습니다") {
		t.Errorf("nothing was hidden:\n%.300s\n%s", out, se)
	}
	if !strings.Contains(out, "AR-006") {
		t.Errorf("the file itself should be reported:\n%.300s", out)
	}
}

func TestReportJSONUnchangedByUntrusted(t *testing.T) {
	useFakeDeps(t)
	for _, args := range [][]string{{}, {"--untrusted"}} {
		dir := t.TempDir()
		all := append([]string{"scan", sampleApp, "--format", "json", "--out", dir}, args...)
		if code, _, se := runCLI(t, all...); code == 2 {
			t.Fatalf("exit 2: %s", se)
		}
		b, err := os.ReadFile(filepath.Join(dir, "adk-report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["untrusted"]; ok {
			t.Errorf("%v: adk-report.json has an untrusted key", args)
		}
	}
}

type targetSpy struct{ got *checker.Target }

func (targetSpy) Name() string { return "spy" }
func (s targetSpy) Run(_ context.Context, t checker.Target) (checker.Result, error) {
	*s.got = t
	return checker.Result{Findings: []finding.Finding{}}, nil
}

func TestUntrustedReachesCheckers(t *testing.T) {
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	var got checker.Target
	defaultCheckers = func(fs.FS, scanOptions) []checker.Checker { return []checker.Checker{targetSpy{&got}} }
	root := t.TempDir()
	runCLI(t, "scan", root)
	if got.Untrusted {
		t.Errorf("Untrusted set without the flag")
	}
	runCLI(t, "scan", root, "--untrusted")
	if !got.Untrusted {
		t.Errorf("Untrusted not set with the flag")
	}
}

func TestUntrustedOnlyOnScan(t *testing.T) {
	if !strings.Contains(usageText, "--untrusted") || strings.Count(usageText, "--untrusted") != 1 {
		t.Errorf("usage: %s", usageText)
	}
	if code, _, se := runCLI(t, "assets", "example.test", "--untrusted"); code != 2 || !strings.Contains(se, "untrusted") {
		t.Errorf("assets --untrusted: code=%d stderr=%s", code, se)
	}
}
