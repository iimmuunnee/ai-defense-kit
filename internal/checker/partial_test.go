package checker

import (
	"context"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 점검기가 앞 단계 결과를 남긴 뒤 시간 제한에 걸리면, 그 결과와 경고는 리포트에 남고
// 상태는 실패가 아니라 "일부만 점검"이 된다.
func TestRunAllKeepsPartialResultOnTimeout(t *testing.T) {
	c := fake{"stage", func(ctx context.Context, _ Target) (Result, error) {
		SavePartial(ctx, Result{
			Findings: []finding.Finding{{ID: "cur"}},
			Warnings: []string{"뒤 단계는 다 보지 못함"},
		})
		<-ctx.Done()
		return Result{}, ctx.Err()
	}}
	fs, st := RunAll(context.Background(), []Checker{c}, Target{}, 50*time.Millisecond)
	if len(fs) != 1 || fs[0].ID != "cur" {
		t.Fatalf("findings = %+v, want the saved one", fs)
	}
	if st[0].Status != StatusPartial {
		t.Errorf("status = %q, want %q", st[0].Status, StatusPartial)
	}
	if st[0].Error != "시간 제한(50ms)을 넘겨 중단됨" {
		t.Errorf("error = %q", st[0].Error)
	}
	if len(st[0].Warnings) != 1 || st[0].Warnings[0] != "뒤 단계는 다 보지 못함" {
		t.Errorf("warnings = %v", st[0].Warnings)
	}
}

// 시간 제한 뒤에도 돌아오지 않는 점검기라도 남긴 결과는 쓴다.
func TestRunAllKeepsPartialResultWhenCheckerIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	c := fake{"stuck", func(ctx context.Context, _ Target) (Result, error) {
		SavePartial(ctx, Result{Findings: []finding.Finding{{ID: "cur"}}})
		<-release
		return Result{}, nil
	}}
	start := time.Now()
	fs, st := RunAll(context.Background(), []Checker{c}, Target{}, 50*time.Millisecond)
	if st[0].Status != StatusPartial || len(fs) != 1 {
		t.Errorf("got %+v, findings %+v", st[0], fs)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("RunAll blocked on a checker that ignores ctx")
	}
}

// 다 끝난 점검은 중간에 남긴 결과가 아니라 마지막 결과를 쓴다.
func TestRunAllPrefersFinalResultOverPartial(t *testing.T) {
	c := fake{"done", func(ctx context.Context, _ Target) (Result, error) {
		SavePartial(ctx, Result{Findings: []finding.Finding{{ID: "cur"}}, Warnings: []string{"중간"}})
		return Result{Findings: []finding.Finding{{ID: "cur"}, {ID: "hist"}}}, nil
	}}
	fs, st := RunAll(context.Background(), []Checker{c}, Target{}, time.Second)
	if st[0].Status != StatusOK || len(fs) != 2 || len(st[0].Warnings) != 0 {
		t.Errorf("got %+v, findings %+v", st[0], fs)
	}
}

// 시간 제한이 아닌 오류, 사용자의 중단은 그대로 실패다. 사용자가 멈춘 점검은 리포트를 쓰지 않는다.
func TestRunAllPartialOnlyForTimeout(t *testing.T) {
	errC := fake{"err", func(ctx context.Context, _ Target) (Result, error) {
		SavePartial(ctx, Result{Findings: []finding.Finding{{ID: "cur"}}})
		return Result{}, context.DeadlineExceeded // 시간 제한이 지나지 않았는데 돌려준 오류
	}}
	fs, st := RunAll(context.Background(), []Checker{errC}, Target{}, time.Minute)
	if st[0].Status != StatusFailed || len(fs) != 0 {
		t.Errorf("non-timeout error: %+v, findings %+v", st[0], fs)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelC := fake{"cancel", func(ctx context.Context, _ Target) (Result, error) {
		SavePartial(ctx, Result{Findings: []finding.Finding{{ID: "cur"}}})
		cancel()
		<-ctx.Done()
		return Result{}, ctx.Err()
	}}
	fs, st = RunAll(ctx, []Checker{cancelC}, Target{}, time.Minute)
	if st[0].Status != StatusFailed || st[0].Error != "사용자가 중단함" || len(fs) != 0 {
		t.Errorf("user cancel: %+v, findings %+v", st[0], fs)
	}
}

// 남기는 쪽이 RunAll 밖(직접 Run을 부른 시험)이면 아무 일도 하지 않는다.
func TestSavePartialWithoutRunAllIsNoop(t *testing.T) {
	SavePartial(context.Background(), Result{Findings: []finding.Finding{{ID: "x"}}})
}
