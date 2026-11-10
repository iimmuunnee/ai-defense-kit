package rules

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

type ruleChecker struct{ fsys fs.FS }

// NewChecker returns the checker that runs the YAML rules found in fsys.
func NewChecker(fsys fs.FS) checker.Checker { return ruleChecker{fsys: fsys} }

func (ruleChecker) Name() string { return "rules" }

func (c ruleChecker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	rs, err := Load(c.fsys)
	if err != nil {
		return checker.Result{}, fmt.Errorf("규칙 파일을 불러오지 못함: %w", err)
	}
	found, warns, err := Evaluate(t.Root, t.Stacks, rs, c.fsys)
	if err != nil {
		return checker.Result{}, err
	}
	return checker.Result{Findings: found, Warnings: warns}, nil
}
