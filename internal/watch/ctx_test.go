package watch

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// endless gives bytes for ever and calls onRead on the first read. It fails
// after limit reads, so a reader that does not stop ends in an assertion.
type endless struct {
	onRead func()
	reads  int
	limit  int
}

func (e *endless) Read(p []byte) (int, error) {
	if e.reads == 0 && e.onRead != nil {
		e.onRead()
	}
	e.reads++
	if e.reads > e.limit {
		return 0, errors.New("read past the point where the context ended")
	}
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
func (*endless) Close() error { return nil }

func TestRepoHashStopsWhenTheContextEnds(t *testing.T) {
	root := t.TempDir()
	put(t, root, "yarn.lock", "y")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o := &repoObserver{open: func(string) (io.ReadCloser, error) {
		return &endless{onRead: cancel, limit: 1000}, nil
	}}
	_, err := o.Observe(ctx, repoTarget(map[string]any{"root": root}))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the context's end", err)
	}
}

// hangs blocks until its context ends, as a stuck file system does.
type hangs struct{ ctx context.Context }

func (h hangs) Read([]byte) (int, error) {
	<-h.ctx.Done()
	return 0, h.ctx.Err()
}
func (hangs) Close() error { return nil }

func TestRepoDeadlineKeepsWhatWasRead(t *testing.T) {
	root := t.TempDir()
	put(t, root, "composer.lock", "c")
	put(t, root, "yarn.lock", "y")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	o := &repoObserver{open: func(p string) (io.ReadCloser, error) {
		if strings.HasSuffix(filepath.ToSlash(p), "yarn.lock") {
			return hangs{ctx}, nil
		}
		return os.Open(p)
	}}
	_, err := o.Observe(ctx, repoTarget(map[string]any{"root": root}))
	var pe PartialError
	if !errors.As(err, &pe) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if pe.Obs["file:composer.lock"] != sum("c") {
		t.Errorf("partial = %v", pe.Obs)
	}
}

// The context ends in the middle of one long value: it must read as that, not
// as a broken file.
func TestPodsStreamStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := io.MultiReader(strings.NewReader(`{"kind":"List","note":"`), &endless{onRead: cancel, limit: 12})
	_, err := readPods(ctx, r)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the context's end", err)
	}
	if err != nil && strings.Contains(err.Error(), "JSON") {
		t.Errorf("a cancelled read was reported as a broken file: %v", err)
	}
}
