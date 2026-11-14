package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// "일부만 점검"은 --strict에서 실패와 같이 종료 코드 2를 만들고, 결과가 먼저다.
func TestExitCodePartial(t *testing.T) {
	high := []finding.Finding{{Severity: finding.High}}
	partial := []checker.CheckStatus{{Name: "secrets", Status: checker.StatusPartial}}
	if got := ExitCode(nil, partial, nil, true); got != 2 {
		t.Errorf("partial under strict = %d, want 2", got)
	}
	if got := ExitCode(nil, partial, nil, false); got != 0 {
		t.Errorf("partial without strict = %d, want 0", got)
	}
	if got := ExitCode(high, partial, sev(finding.High), true); got != 1 {
		t.Errorf("finding beats partial = %d, want 1", got)
	}
}

func TestWarnChecksShowsPartial(t *testing.T) {
	var buf bytes.Buffer
	warnChecks(&buf, []checker.CheckStatus{{Name: "secrets", Status: checker.StatusPartial,
		Error: "시간 제한(5m0s)을 넘겨 중단됨", Warnings: []string{"과거 커밋을 다 보지 못함"}}})
	out := buf.String()
	for _, want := range []string{"일부 점검을 하지 못했습니다", "secrets (일부만 점검): 시간 제한(5m0s)을 넘겨 중단됨", "secrets: 과거 커밋을 다 보지 못함"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

// stagedChecker saves a first-stage result and then waits for its timeout.
type stagedChecker struct{}

func (stagedChecker) Name() string { return "secrets" }
func (stagedChecker) Run(ctx context.Context, _ checker.Target) (checker.Result, error) {
	checker.SavePartial(ctx, checker.Result{
		Findings: []finding.Finding{{ID: "SECRET-x", Source: "secrets", Kind: "secret-current", Severity: finding.High,
			Location: "config.py", Evidence: "K7Q2****", Fingerprint: "1111222233334444"}},
		Warnings: []string{"과거 커밋을 다 보지 못함"},
	})
	<-ctx.Done()
	return checker.Result{}, ctx.Err()
}

// 점검기 하나만 있고 그것이 일부만 점검으로 끝나도 리포트는 쓰고, 찾은 결과가 들어간다.
func TestScanReportsPartialCheck(t *testing.T) {
	oldC, oldT := defaultCheckers, checkerTimeout
	t.Cleanup(func() { defaultCheckers, checkerTimeout = oldC, oldT })
	checkerTimeout = 50 * time.Millisecond
	defaultCheckers = func(fs.FS, scanOptions) []checker.Checker { return []checker.Checker{stagedChecker{}} }

	code, stdout, stderr := runCLI(t, "scan", sampleApp, "--format", "json", "--fail-on", "none", "--strict")
	if code != 2 {
		t.Errorf("code = %d, want 2 (partial under --strict): %s", code, stderr)
	}
	if !strings.Contains(stderr, "secrets (일부만 점검)") {
		t.Errorf("stderr lacks the partial check: %q", stderr)
	}
	var rep struct {
		Findings []struct{ Fingerprint string }
		Checks   []struct{ Name, Status string }
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Fingerprint != "1111222233334444" {
		t.Errorf("findings = %+v", rep.Findings)
	}
	if len(rep.Checks) != 1 || rep.Checks[0].Status != "partial" {
		t.Errorf("checks = %+v", rep.Checks)
	}
}
