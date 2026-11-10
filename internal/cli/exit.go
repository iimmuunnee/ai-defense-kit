// Package cli implements the adk command line.
package cli

import (
	"fmt"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// ParseFailOn parses a --fail-on value: critical, high, medium or low, or
// none, which returns nil (findings never make the exit code 1).
func ParseFailOn(v string) (*finding.Severity, error) {
	if v == "none" {
		return nil, nil
	}
	s, err := finding.ParseSeverity(v)
	if err != nil || s == finding.Info {
		return nil, fmt.Errorf("--fail-on 값이 올바르지 않습니다: %q (critical, high, medium, low, none 중 하나)", v)
	}
	return &s, nil
}

// ExitCode maps results to a process exit code, one table for every command:
// 1 = something at or above failOn (nil means --fail-on none; Info never
// counts), else 2 = a checker failed under strict, else 0. A finding beats a
// failed check, as in watch and device.
func ExitCode(fs []finding.Finding, st []checker.CheckStatus, failOn *finding.Severity, strict bool) int {
	if finding.AtOrAbove(fs, failOn) {
		return 1
	}
	if strict {
		for _, s := range st {
			if s.Status == checker.StatusFailed {
				return 2
			}
		}
	}
	return 0
}
