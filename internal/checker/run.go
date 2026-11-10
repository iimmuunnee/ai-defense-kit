package checker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

type outcome struct {
	res Result
	err error
}

// RunAll runs every checker in its own goroutine with its own timeout
// (timeout <= 0 means no per-checker timeout). Panics are recovered and
// recorded as failed. On any error the checker's findings are discarded and
// its warnings and External records kept; on success both are kept. Statuses follow the order of cs.
func RunAll(ctx context.Context, cs []Checker, t Target, timeout time.Duration) ([]finding.Finding, []CheckStatus) {
	outs := make([]outcome, len(cs))
	done := make([]chan struct{}, len(cs))

	for i, c := range cs {
		done[i] = make(chan struct{})
		go func() {
			defer close(done[i])
			outs[i] = runOne(ctx, c, t, timeout)
		}()
	}

	var all []finding.Finding
	statuses := make([]CheckStatus, len(cs))
	// Every finding passes here on its way to a report: a last net over what is
	// shown (evidence and title), whichever checker made it. It hides only the
	// narrow shapes (finding.ScrubNarrow), so separators inside a sentence the
	// tool composed are never counted. A checker that puts a repository fragment
	// (a job name, a table or host name, a command) into a sentence scans that
	// fragment itself first. Fingerprints are left as each checker made them.
	for i, c := range cs {
		<-done[i]
		o := outs[i]
		st := CheckStatus{Name: c.Name(), Status: StatusOK, Warnings: o.res.Warnings, External: o.res.External}
		switch {
		case o.err == nil:
			for _, f := range o.res.Findings {
				f.Evidence, f.Title = finding.ScrubNarrow(f.Evidence), finding.ScrubNarrow(f.Title)
				all = append(all, f)
			}
		case errors.Is(o.err, ErrSkipped):
			st.Status = StatusSkipped
			st.Error = strings.TrimPrefix(o.err.Error(), ErrSkipped.Error()+": ")
		default:
			st.Status = StatusFailed
			st.Error = o.err.Error()
		}
		statuses[i] = st
	}
	return all, statuses
}

// runOne runs a single checker, bounded by the timeout even if the checker
// ignores its context, and converts panics into errors.
func runOne(parent context.Context, c Checker, t Target, timeout time.Duration) outcome {
	ctx := parent
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, timeout)
		defer cancel()
	}

	ch := make(chan outcome, 1) // buffered: an abandoned checker can still send and exit
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- outcome{err: fmt.Errorf("panic: %v", r)}
			}
		}()
		res, err := c.Run(ctx, t)
		ch <- outcome{res: res, err: err}
	}()

	var o outcome
	select {
	case o = <-ch:
	case <-ctx.Done():
		o = outcome{err: ctx.Err()}
	}
	if o.err != nil && ctx.Err() != nil {
		o.err = stopped(parent, ctx, timeout)
	}
	return o
}

// stopErr is a context stop shown in Korean that still unwraps to the
// context error.
type stopErr struct {
	msg string
	err error
}

func (e stopErr) Error() string { return e.msg }
func (e stopErr) Unwrap() error { return e.err }

// stopped explains why ctx ended: the user cancelled (the parent ended) or
// the per-checker timeout passed.
func stopped(parent, ctx context.Context, timeout time.Duration) error {
	if parent.Err() != nil {
		return stopErr{msg: "사용자가 중단함", err: parent.Err()}
	}
	return stopErr{msg: fmt.Sprintf("시간 제한(%s)을 넘겨 중단됨", timeout), err: ctx.Err()}
}
