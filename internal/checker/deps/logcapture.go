package deps

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

// setLogger is a seam over osvscanner.SetLogger so tests can emit log records
// the same way osv-scanner does.
var setLogger = osvscanner.SetLogger

// scanMu guards the process-global osv-scanner logger.
var scanMu sync.Mutex

// errCapture is a slog.Handler that keeps the first Error-level message and
// drops everything else, so osv-scanner never writes to the user's stderr.
type errCapture struct {
	mu    sync.Mutex
	first string
}

func (h *errCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *errCapture) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		h.mu.Lock()
		if h.first == "" {
			h.first = r.Message
		}
		h.mu.Unlock()
	}
	return nil
}

func (h *errCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *errCapture) WithGroup(string) slog.Handler      { return h }

func (h *errCapture) firstError() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.first
}

// quietScan runs scan with osv-scanner's logging captured. It returns the
// first Error-level log message, if any.
func quietScan(scan ScanFunc, a osvscanner.ScannerActions) (resultsAndErr scanOut, logged string) {
	scanMu.Lock()
	defer scanMu.Unlock()
	h := &errCapture{}
	setLogger(h)
	defer setLogger(&errCapture{}) // keep later osv-scanner output silent
	resultsAndErr.res, resultsAndErr.err = scan(a)
	return resultsAndErr, h.firstError()
}
