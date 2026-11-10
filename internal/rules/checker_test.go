package rules

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

func TestCheckerRunsAndReportsLoadError(t *testing.T) {
	c := NewChecker(rulesFS(vulnRule))
	if c.Name() != "rules" {
		t.Fatal(c.Name())
	}
	root := t.TempDir()
	write(t, root, "w.py", "portone\n")
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("err=%v res=%v", err, res)
	}
	_, err = NewChecker(fstest.MapFS{"rules/x.yaml": {Data: []byte("title: t")}}).Run(context.Background(), checker.Target{Root: root})
	if err == nil {
		t.Fatal("want load error")
	}
}
