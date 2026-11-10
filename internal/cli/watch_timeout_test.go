package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// stuckObserver takes no notice of its context.
type stuckObserver struct{ release chan struct{} }

func (stuckObserver) Kind() string { return "stuck" }
func (o stuckObserver) Observe(context.Context, watch.Target) (watch.Observation, error) {
	<-o.release
	return watch.Observation{}, nil
}

type quickObserver struct{}

func (quickObserver) Kind() string { return "quick" }
func (quickObserver) Observe(context.Context, watch.Target) (watch.Observation, error) {
	return watch.Observation{"v": "1"}, nil
}

// An observer that hangs and ignores its context must not hold up the next one.
func TestCollectDoesNotWaitForAStuckObserver(t *testing.T) {
	old := targetGrace
	targetGrace = 100 * time.Millisecond
	defer func() { targetGrace = old }()
	release := make(chan struct{})
	defer close(release)
	type result struct {
		cur    map[string]watch.Observation
		failed map[string]error
	}
	done := make(chan result, 1)
	go func() {
		cur, failed := collectWith(context.Background(), []watch.Observer{stuckObserver{release}, quickObserver{}},
			[]watch.Target{{Key: "a", Kind: "stuck"}, {Key: "b", Kind: "quick"}}, newScrubber(), 200*time.Millisecond)
		done <- result{cur, failed}
	}()
	select {
	case r := <-done:
		if r.cur["b"]["v"] != "1" {
			t.Errorf("the target after the stuck one was not read: %v", r.cur)
		}
		if err := r.failed["a"]; err == nil || !strings.Contains(err.Error(), "--target-timeout") {
			t.Errorf("the stuck target's reason = %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("collect is still waiting for the stuck observer")
	}
}

// Cancelling is not a timeout, and says nothing of a time limit.
func TestCollectCancelledIsNotATimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	defer close(release)
	cancel()
	_, failed := collectWith(ctx, []watch.Observer{stuckObserver{release}}, []watch.Target{{Key: "a", Kind: "stuck"}}, newScrubber(), time.Hour)
	if err := failed["a"]; err != nil && strings.Contains(err.Error(), "--target-timeout") {
		t.Errorf("err = %v", err)
	}
}

func hangingPage(t *testing.T) (url string, hang *atomic.Bool) {
	t.Helper()
	hang = &atomic.Bool{}
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="/a.js"></script>`)
		case hang.Load():
			select {
			case <-stop:
			case <-r.Context().Done():
			}
		default:
			fmt.Fprint(w, "a")
		}
	}))
	t.Cleanup(func() { close(stop); srv.Close() })
	return srv.URL + "/", hang
}

func TestWatchHangingTargetDoesNotHoldUpTheNext(t *testing.T) {
	url, hang := hangingPage(t)
	w := newWsp(t)
	root := t.TempDir()
	writeRepoFile(t, root, "ci.yml", "1")
	cfg := fmt.Sprintf("targets:\n  - key: a-page\n    kind: web-scripts\n    options:\n      url: \"%s\"\n  - key: b-repo\n    kind: repo-files\n    options:\n      root: \"%s\"\n      globs: [\"*.yml\"]\n", url, filepath.ToSlash(root))
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mustInit(t, w)
	hang.Store(true)
	writeRepoFile(t, root, "ci.yml", "2")
	code, out, errs := w.run("check", "--format", "json", "--target-timeout", "1s")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	rep := parseReport(t, out)
	if ids := rep.ids(); len(ids) != 1 || ids[0] != "WA-102" {
		t.Errorf("findings = %v", ids)
	}
	if status, why, _ := rep.check("watch/a-page"); status != "failed" || !strings.Contains(why, "--target-timeout") || strings.Contains(why, "context") {
		t.Errorf("a-page: %s %q", status, why)
	}
	// Past the limit is not read, so it cannot be accepted or start a baseline.
	if code, _, errs := w.run("accept", "a-page", "--note", "x", "--target-timeout", "1s"); code != 2 || !strings.Contains(errs, "--target-timeout") {
		t.Errorf("accept = %d\n%s", code, errs)
	}
	if err := os.Remove(w.base); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w.run("init", "--target-timeout", "1s"); code != 2 || fileExists(w.base) {
		t.Errorf("init = %d\n%s", code, errs)
	}
}

func TestWatchTargetTimeoutFlag(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	for _, bad := range []string{"0", "0s", "-1s", "soon", ""} {
		code, _, errs := w.run("check", "--target-timeout", bad)
		if code != 2 || !strings.Contains(errs, "0보다 큰") {
			t.Errorf("%q: code=%d %s", bad, code, errs)
		}
	}
	if code, out, errs := w.run("check", "--target-timeout", "1m"); code != 0 {
		t.Errorf("check: code=%d\n%s\n%s", code, out, errs)
	}
	if code, out, errs := w.run("accept", "hot", "--note", "x", "--target-timeout", "1m"); code != 0 {
		t.Errorf("accept: code=%d\n%s\n%s", code, out, errs)
	}
	var o, e strings.Builder
	if code := Run(context.Background(), []string{"watch", "--help"}, &o, &e); code != 0 || !strings.Contains(o.String(), "--target-timeout") {
		t.Errorf("watch usage lacks the flag: %s", o.String())
	}
	if strings.Contains(usageText, "--target-timeout") {
		t.Error("the usage text that scan and assets print must stay as it was")
	}
}

func TestTargetTimeoutIsDocumented(t *testing.T) {
	s := readFile(t, "../../docs/watch.md")
	for _, want := range []string{"`--target-timeout`", "200개", "기본 2분"} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
}
