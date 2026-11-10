package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

type fake struct {
	name string
	run  func(ctx context.Context, t Target) (Result, error)
}

func (f fake) Name() string { return f.name }
func (f fake) Run(ctx context.Context, t Target) (Result, error) {
	return f.run(ctx, t)
}

func TestRunAllIsolatesFailures(t *testing.T) {
	okC := fake{"ok", func(context.Context, Target) (Result, error) {
		return Result{
			Findings: []finding.Finding{{ID: "a"}, {ID: "b"}},
			Warnings: []string{"일부만 성공"},
		}, nil
	}}
	errC := fake{"err", func(context.Context, Target) (Result, error) {
		return Result{Findings: []finding.Finding{{ID: "x"}}, Warnings: []string{"w"}}, errors.New("boom")
	}}
	panicC := fake{"panic", func(context.Context, Target) (Result, error) {
		panic("kaboom")
	}}
	skipC := fake{"skip", func(context.Context, Target) (Result, error) {
		return Result{Findings: []finding.Finding{{ID: "y"}}}, fmt.Errorf("%w: 오프라인", ErrSkipped)
	}}

	fs, st := RunAll(context.Background(), []Checker{okC, errC, panicC, skipC}, Target{}, time.Second)

	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2", len(fs))
	}
	if len(st) != 4 {
		t.Fatalf("statuses = %d, want 4", len(st))
	}
	for i, name := range []string{"ok", "err", "panic", "skip"} {
		if st[i].Name != name {
			t.Errorf("st[%d].Name = %q, want %q", i, st[i].Name, name)
		}
	}
	if st[0].Status != StatusOK || len(st[0].Warnings) != 1 {
		t.Errorf("ok: %+v", st[0])
	}
	if st[1].Status != StatusFailed || st[1].Error != "boom" {
		t.Errorf("err: %+v", st[1])
	}
	if len(st[1].Warnings) != 1 {
		t.Errorf("failed checker should keep warnings: %+v", st[1])
	}
	if st[2].Status != StatusFailed || !strings.Contains(st[2].Error, "kaboom") {
		t.Errorf("panic: %+v", st[2])
	}
	if st[3].Status != StatusSkipped || st[3].Error != "오프라인" {
		t.Errorf("skip: %+v", st[3])
	}
}

func TestRunAllTimeout(t *testing.T) {
	wait := fake{"wait", func(ctx context.Context, _ Target) (Result, error) {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}}
	start := time.Now()
	_, st := RunAll(context.Background(), []Checker{wait}, Target{}, 50*time.Millisecond)
	if st[0].Status != StatusFailed || st[0].Error != "시간 제한(50ms)을 넘겨 중단됨" {
		t.Errorf("got %+v", st[0])
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took too long")
	}
}

func TestRunAllTimeoutWhenCheckerIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := fake{"stuck", func(context.Context, Target) (Result, error) {
		<-release
		return Result{}, nil
	}}
	start := time.Now()
	_, st := RunAll(context.Background(), []Checker{stuck}, Target{}, 50*time.Millisecond)
	if st[0].Status != StatusFailed || st[0].Error != "시간 제한(50ms)을 넘겨 중단됨" {
		t.Errorf("got %+v", st[0])
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("RunAll blocked on a checker that ignores ctx")
	}
}

func TestRunAllEmpty(t *testing.T) {
	fs, st := RunAll(context.Background(), nil, Target{}, time.Second)
	if len(fs) != 0 || len(st) != 0 {
		t.Errorf("got %v %v", fs, st)
	}
}

func TestRunAllParentCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wait := fake{"wait", func(ctx context.Context, _ Target) (Result, error) {
		cancel()
		<-ctx.Done()
		return Result{}, fmt.Errorf("osv: %w", ctx.Err())
	}}
	_, st := RunAll(ctx, []Checker{wait}, Target{}, time.Minute)
	if st[0].Status != StatusFailed || st[0].Error != "사용자가 중단함" {
		t.Errorf("got %+v", st[0])
	}
}

func TestRunAllKeepsExternalOnError(t *testing.T) {
	t0 := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	ext := []ExternalData{{Name: "OSV", Mode: ModeOnline, Status: ExternalFailed}, {Name: "CISA KEV", Mode: ModeOnline, Status: ExternalUsed, FetchedAt: &t0}}
	errC := fake{"err", func(context.Context, Target) (Result, error) {
		return Result{External: ext}, errors.New("boom")
	}}
	skipC := fake{"skip", func(context.Context, Target) (Result, error) {
		return Result{External: ext[:1]}, fmt.Errorf("%w: x", ErrSkipped)
	}}
	_, st := RunAll(context.Background(), []Checker{errC, skipC}, Target{}, time.Second)
	if st[0].Status != StatusFailed || len(st[0].External) != 2 || st[0].External[1].FetchedAt == nil || !st[0].External[1].FetchedAt.Equal(t0) {
		t.Errorf("failed checker should keep External: %+v", st[0])
	}
	if st[1].Status != StatusSkipped || len(st[1].External) != 1 {
		t.Errorf("skipped checker should keep External: %+v", st[1])
	}
}

func TestScanJSONUnchangedByExternal(t *testing.T) {
	b, err := json.Marshal(CheckStatus{Name: "deps", Status: StatusOK, External: []ExternalData{{Name: "OSV"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "external") || strings.Contains(string(b), "External") {
		t.Errorf("JSON must not contain external: %s", b)
	}
}
