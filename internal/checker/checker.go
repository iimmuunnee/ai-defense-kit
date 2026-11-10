// Package checker defines the Checker interface and a runner that isolates failures.
package checker

import (
	"context"
	"errors"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Target describes what to scan.
type Target struct {
	Root    string
	Domain  string
	Stacks  []string
	Offline bool
	// Untrusted says the repository is someone else's: settings it holds that
	// could hide results are not used.
	Untrusted bool
}

// Result is what a checker returns: findings plus non-fatal warnings
// (for partially successful runs).
type Result struct {
	Findings []finding.Finding
	Warnings []string
	External []ExternalData
}

// 외부 데이터를 쓴 결과.
const (
	ExternalUsed    = "used"
	ExternalFailed  = "failed"
	ExternalSkipped = "skipped"
)

// 외부 데이터를 받은 방식.
const (
	ModeOnline  = "online"
	ModeOffline = "offline"
)

// ExternalData records one external data source a checker used (or tried to):
// what it was, how it was read, whether it worked and when it was fetched.
// FetchedAt is nil when the time is unknown (offline DB, failure, skipped).
type ExternalData struct {
	Name      string     `json:"name"`
	Mode      string     `json:"mode"`
	Status    string     `json:"status"`
	FetchedAt *time.Time `json:"fetched_at"`
	Note      string     `json:"note,omitempty"`
}

// Checker is one scan unit (secrets, deps, ...).
type Checker interface {
	Name() string
	Run(ctx context.Context, t Target) (Result, error)
}

// Status is the outcome of one checker.
type Status string

const (
	StatusOK      Status = "ok"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// CheckStatus records how one checker ended.
type CheckStatus struct {
	Name     string   `json:"name"`
	Status   Status   `json:"status"`
	Error    string   `json:"error"`
	Warnings []string `json:"warnings"`
	// Notes are remarks on a check that did complete. Unlike Warnings they do
	// not say that anything is missing from the results.
	Notes []string `json:"notes,omitempty"`
	// External is not part of adk-report.json.
	External []ExternalData `json:"-"`
}

// ErrSkipped marks a checker that chose not to run. Return
// fmt.Errorf("%w: reason", ErrSkipped) to be recorded as skipped, not failed.
var ErrSkipped = errors.New("skipped")
