package secrets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zricethezav/gitleaks/v8/report"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

// 과거 기록 점검이 시간 제한에 걸려도 현재 파일에서 찾은 비밀 키는 리포트에 남고,
// "과거 기록은 다 보지 못함" 경고가 붙으며 상태는 "일부만 점검"이다.
func TestHistoryTimeoutKeepsCurrentFindings(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "config.py", configLine(fakeKey(t)))
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "c1")

	full := run(t, root)
	var want string
	for _, f := range full.Findings {
		if f.Kind == "secret-current" {
			want = f.Fingerprint
		}
	}
	if want == "" {
		t.Fatalf("full run found no current secret: %+v", full)
	}

	old := historyScanner
	t.Cleanup(func() { historyScanner = old })
	historyScanner = func(ctx context.Context, _ string, _ bool) ([]report.Finding, bool, error) {
		<-ctx.Done()
		return nil, false, ctx.Err()
	}

	fs, st := checker.RunAll(context.Background(), []checker.Checker{New(aidefensekit.Data)}, checker.Target{Root: root}, 3*time.Second)
	if st[0].Status != checker.StatusPartial {
		t.Fatalf("status = %+v, want partial", st[0])
	}
	if len(fs) != 1 || fs[0].Kind != "secret-current" {
		t.Fatalf("findings = %+v, want the current-file secret only", fs)
	}
	if fs[0].Fingerprint != want {
		t.Errorf("fingerprint %s differs from a full run's %s", fs[0].Fingerprint, want)
	}
	if len(st[0].Warnings) != 1 || st[0].Warnings[0] != warnHistoryUnfinished {
		t.Errorf("warnings = %v", st[0].Warnings)
	}
	if !strings.Contains(warnHistoryUnfinished, "과거") {
		t.Errorf("warning must say past commits were not fully checked: %q", warnHistoryUnfinished)
	}
}

// 현재 파일 점검이 끝나기 전에 시간 제한에 걸리면 남길 결과가 없어 실패다.
func TestCurrentFilesTimeoutStillFails(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.py", configLine(fakeKey(t)))
	old := fileScanner
	t.Cleanup(func() { fileScanner = old })
	fileScanner = func(ctx context.Context, _ string, _ bool) ([]report.Finding, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	fs, st := checker.RunAll(context.Background(), []checker.Checker{New(aidefensekit.Data)}, checker.Target{Root: root}, 100*time.Millisecond)
	if st[0].Status != checker.StatusFailed || len(fs) != 0 {
		t.Errorf("got %+v, findings %+v", st[0], fs)
	}
}
