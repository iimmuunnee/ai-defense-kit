package checker

import (
	"context"
	"sync"
)

type partialKey struct{}

// partialBox holds the last result a checker saved with SavePartial.
type partialBox struct {
	mu  sync.Mutex
	res *Result
}

func (b *partialBox) get() (Result, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.res == nil {
		return Result{}, false
	}
	return *b.res, true
}

// SavePartial records the results a checker has finished so far, so that if
// its timeout stops it later RunAll reports them instead of nothing. r must be
// complete in itself: its findings are final and its warnings say what the
// later stages would have added. A later call replaces an earlier one, and a
// checker that returns normally is reported from its return value alone. The
// checker must not change r's slices afterwards. Outside RunAll it does nothing.
func SavePartial(ctx context.Context, r Result) {
	b, ok := ctx.Value(partialKey{}).(*partialBox)
	if !ok {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.res = &r
}
