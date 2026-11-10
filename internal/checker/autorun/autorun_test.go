package autorun

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"unicode"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

var testData = fstest.MapFS{
	"explain/AR-001.md": {Data: []byte("설명 AR-001")},
	"explain/AR-004.md": {Data: []byte("설명 AR-004")},
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, root string) checker.Result {
	t.Helper()
	res, err := New(testData).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// summarize turns findings into sorted "ID|severity|confidence|location|line|evidence" lines.
func summarize(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s|%s|%s|%s|%d|%s", f.ID, f.Severity, f.Confidence, f.Location, f.Line, f.Evidence))
	}
	sort.Strings(out)
	return out
}

func expectFindings(t *testing.T, root string, want ...string) checker.Result {
	t.Helper()
	res := run(t, root)
	sort.Strings(want)
	got := summarize(res.Findings)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings\n got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}
	return res
}

func TestName(t *testing.T) {
	if New(testData).Name() != CheckerName || CheckerName != "autorun" {
		t.Fatal("name")
	}
}

func TestAutorunFindings(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			"tasks folderOpen",
			map[string]string{".vscode/tasks.json": `{"version":"2.0.0","tasks":[
				{"label":"dev","type":"shell","command":"node","args":["a.js","--x"],"runOptions":{"runOn":"folderOpen"}},
				{"label":"build","command":"make","runOptions":{"runOn":"default"}}]}`},
			[]string{`AR-001|high|certain|.vscode/tasks.json|0|dev: {"command":"node","args":["a.js","--x"],"label":"dev","runOptions":{"runOn":"folderOpen"},"type":"shell"}`},
		},
		{
			"tasks without label use a number",
			map[string]string{".vscode/tasks.json": `{"tasks":[{"command":"node x.js","runOptions":{"runOn":"folderOpen"}}]}`},
			[]string{`AR-001|high|certain|.vscode/tasks.json|0|1: {"command":"node x.js","runOptions":{"runOn":"folderOpen"}}`},
		},
		{
			"devcontainer.json",
			map[string]string{".devcontainer/devcontainer.json": `{"image":"x",
				"initializeCommand":"echo init",
				"onCreateCommand":"echo a",
				"updateContentCommand":"echo b",
				"postCreateCommand":"echo c",
				"postStartCommand":"echo d",
				"postAttachCommand":"echo e"}`},
			[]string{
				"AR-002|high|certain|.devcontainer/devcontainer.json|0|initializeCommand: echo init",
				"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|onCreateCommand: echo a",
				"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|updateContentCommand: echo b",
				"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|postCreateCommand: echo c",
				"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|postStartCommand: echo d",
				"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|postAttachCommand: echo e",
			},
		},
		{
			"devcontainer subfolder and dotfile",
			map[string]string{
				".devcontainer/py/devcontainer.json": `{"postCreateCommand":"pip install ."}`,
				".devcontainer.json":                 `{"initializeCommand":"echo hi"}`,
			},
			[]string{
				"AR-003|medium|suspect|.devcontainer/py/devcontainer.json|0|postCreateCommand: pip install .",
				"AR-002|high|certain|.devcontainer.json|0|initializeCommand: echo hi",
			},
		},
		{
			"mcp servers",
			map[string]string{
				".mcp.json":             `{"mcpServers":{"fs":{"command":"npx","args":["-y","mcp-fs","."]},"remote":{"url":"https://example.com/mcp"}}}`,
				".cursor/mcp.json":      `{"mcpServers":{"tool":{"command":"node","args":["server.js"]}}}`,
				".claude/settings.json": `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo pre"},{"type":"prompt","command":"ignored"}]}],"Stop":[{"hooks":[{"type":"command","command":"echo stop"}]}]}}`,
			},
			[]string{
				`AR-004|medium|suspect|.mcp.json|0|fs: {"command":"npx","args":["-y","mcp-fs","."]}`,
				`AR-004|medium|suspect|.mcp.json|0|remote: {"url":"https://example.com/mcp"}`,
				`AR-004|medium|suspect|.cursor/mcp.json|0|tool: {"command":"node","args":["server.js"]}`,
				`AR-004|medium|suspect|.claude/settings.json|0|PreToolUse: {"command":"echo pre","type":"command"}`,
				`AR-004|medium|suspect|.claude/settings.json|0|Stop: {"command":"echo stop","type":"command"}`,
			},
		},
		{
			"package.json scripts",
			map[string]string{"package.json": `{"scripts":{"preinstall":"node a.js","build":"tsc","postinstall":"node b.js","test":"jest","install":"node-gyp rebuild","prepare":"husky"}}`},
			[]string{
				"AR-005|low|suspect|package.json|0|preinstall: node a.js",
				"AR-005|low|suspect|package.json|0|install: node-gyp rebuild",
				"AR-005|low|suspect|package.json|0|postinstall: node b.js",
				"AR-005|low|suspect|package.json|0|prepare: husky",
			},
		},
		{
			"nested package.json",
			map[string]string{"web/package.json": `{"scripts":{"postinstall":"node b.js"}}`},
			[]string{"AR-005|low|suspect|web/package.json|0|postinstall: node b.js"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, content := range c.files {
				write(t, root, rel, content)
			}
			res := expectFindings(t, root, c.want...)
			for _, f := range res.Findings {
				if f.Source != "autorun" || f.Kind != f.ID || f.Title == "" || f.Fingerprint == "" || f.Line != 0 {
					t.Errorf("bad finding %+v", f)
				}
				if strings.ContainsAny(f.Location, `\`) || filepath.IsAbs(f.Location) {
					t.Errorf("location %q", f.Location)
				}
			}
		})
	}
}

func TestAutorunExplainText(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","command":"x","runOptions":{"runOn":"folderOpen"}}]}`)
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"x"}}}`)
	write(t, root, "package.json", `{"scripts":{"postinstall":"x"}}`)
	for _, f := range run(t, root).Findings {
		switch f.ID {
		case "AR-001", "AR-004":
			if f.ExplainKo != "설명 "+f.ID {
				t.Errorf("%s explain = %q", f.ID, f.ExplainKo)
			}
		case "AR-005":
			if f.ExplainKo != "" {
				t.Errorf("missing explain file should give empty text, got %q", f.ExplainKo)
			}
		}
	}
	// No data at all (--rules-dir) still works.
	res, err := New(nil).Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) != 3 {
		t.Fatalf("nil data: %v %d", err, len(res.Findings))
	}
}

func TestAutorunSafeExamples(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"version":"2.0.0","tasks":[
		{"label":"default","command":"make","runOptions":{"runOn":"default"}},
		{"label":"plain","command":"make"},
		{"label":"opts","command":"make","runOptions":{"reevaluateOnRerun":true}}]}`)
	write(t, root, ".vscode/settings.json", `{"task.allowAutomaticTasks":"on"}`)
	write(t, root, "package.json", `{"scripts":{"build":"tsc","test":"jest","start":"node ."}}`)
	write(t, root, ".mcp.json", `{"mcpServers":{"nothing":{"env":{"A":"b"}},"empty":{"command":""}}}`)
	write(t, root, ".devcontainer/devcontainer.json", `{"image":"mcr.microsoft.com/devcontainers/base","postCreateCommand":"","postStartCommand":[],"onCreateCommand":{}}`)
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"hooks":[{"type":"prompt","command":"x"}]}]},"permissions":{}}`)
	expectFindings(t, root)
}

func TestAutorunNoConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, "README.md", "hello")
	write(t, root, "src/main.go", "package main")
	res := run(t, root)
	if len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestAutorunCaseInsensitivePaths(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".VSCode/Tasks.JSON", `{"tasks":[{"label":"x","command":"c","runOptions":{"runOn":"folderOpen"}}]}`)
	write(t, root, ".Devcontainer/DevContainer.json", `{"initializeCommand":"echo hi"}`)
	write(t, root, ".Devcontainer/Sub/DEVCONTAINER.json", `{"postStartCommand":"echo s"}`)
	write(t, root, ".MCP.json", `{"mcpServers":{"m":{"command":"node"}}}`)
	write(t, root, ".Cursor/MCP.json", `{"mcpServers":{"c":{"command":"node"}}}`)
	write(t, root, ".CLAUDE/Settings.JSON", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo"}]}]}}`)
	write(t, root, "Package.JSON", `{"scripts":{"postinstall":"node"}}`)
	expectFindings(t, root,
		`AR-001|high|certain|.VSCode/Tasks.JSON|0|x: {"command":"c","label":"x","runOptions":{"runOn":"folderOpen"}}`,
		"AR-002|high|certain|.Devcontainer/DevContainer.json|0|initializeCommand: echo hi",
		"AR-003|medium|suspect|.Devcontainer/Sub/DEVCONTAINER.json|0|postStartCommand: echo s",
		`AR-004|medium|suspect|.MCP.json|0|m: {"command":"node"}`,
		`AR-004|medium|suspect|.Cursor/MCP.json|0|c: {"command":"node"}`,
		`AR-004|medium|suspect|.CLAUDE/Settings.JSON|0|Stop: {"command":"echo","type":"command"}`,
		"AR-005|low|suspect|Package.JSON|0|postinstall: node",
	)
}

func TestAutorunJSONC(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", "\xef\xbb\xbf// comment\n{\n  /* block */\n  \"version\": \"2.0.0\",\n  \"tasks\": [\n    {\n      \"label\": \"dev\", // trailing\n      \"command\": \"node\",\n      \"args\": [\"a.js\",],\n      \"runOptions\": {\"runOn\": \"folderOpen\",},\n    },\n  ],\n}\n")
	write(t, root, ".devcontainer/devcontainer.json", "\xef\xbb\xbf{\n // c\n \"postCreateCommand\": \"echo a\",\n}\n")
	expectFindings(t, root,
		`AR-001|high|certain|.vscode/tasks.json|0|dev: {"command":"node","args":["a.js"],"label":"dev","runOptions":{"runOn":"folderOpen"}}`,
		"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|postCreateCommand: echo a",
	)
}

func TestAutorunCommandForms(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".devcontainer/devcontainer.json", `{
		"onCreateCommand":"echo str",
		"updateContentCommand":["npm","ci","--quiet"],
		"postCreateCommand":{"web":"npm start","api":"python app.py","x":["a","b"]}
	}`)
	expectFindings(t, root,
		"AR-003|medium|suspect|.devcontainer/devcontainer.json|0|onCreateCommand: echo str",
		`AR-003|medium|suspect|.devcontainer/devcontainer.json|0|updateContentCommand: ["npm","ci","--quiet"]`,
		`AR-003|medium|suspect|.devcontainer/devcontainer.json|0|postCreateCommand: {"api":"python app.py","web":"npm start","x":["a","b"]}`,
	)
}

func TestAutorunNestedRunOptions(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"version":"2.0.0","tasks":[
		{"label":"os","type":"shell","windows":{"command":"calc.exe","runOptions":{"runOn":"folderOpen"}}}],
		"extra":{"command":"z","runOptions":{"runOn":"folderOpen"}}}`)
	expectFindings(t, root,
		`AR-001|high|certain|.vscode/tasks.json|0|os: {"windows":{"command":"calc.exe","runOptions":{"runOn":"folderOpen"}},"label":"os","type":"shell"}`,
		`AR-001|high|certain|.vscode/tasks.json|0|1: {"command":"z","runOptions":{"runOn":"folderOpen"}}`,
	)
}

func TestAutorunSkipDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"node_modules/pkg", "dist", "vendor/x", ".git"} {
		write(t, root, d+"/package.json", `{"scripts":{"postinstall":"node"}}`)
		write(t, root, d+"/.vscode/tasks.json", `{"tasks":[{"label":"a","command":"c","runOptions":{"runOn":"folderOpen"}}]}`)
	}
	expectFindings(t, root)
	write(t, root, "src/package.json", `{"scripts":{"postinstall":"node"}}`)
	expectFindings(t, root, "AR-005|low|suspect|src/package.json|0|postinstall: node")
}

func TestAutorunUnreadable(t *testing.T) {
	const ev = "파일을 해석하지 못했습니다. 직접 확인하세요."
	files := []struct{ rel, id, sev string }{
		{".vscode/tasks.json", "AR-001", "high"},
		{".devcontainer/devcontainer.json", "AR-002", "high"},
		{".mcp.json", "AR-004", "medium"},
		{".cursor/mcp.json", "AR-004", "medium"},
		{".claude/settings.json", "AR-004", "medium"},
		{"package.json", "AR-005", "low"},
	}
	for _, f := range files {
		t.Run(f.rel, func(t *testing.T) {
			broken, big := t.TempDir(), t.TempDir()
			write(t, broken, f.rel, `{"tasks": [ `)
			write(t, big, f.rel, `{"a":"`+strings.Repeat("x", 1<<20)+`"}`)
			fps := map[string]bool{}
			for _, root := range []string{broken, big} {
				res := expectFindings(t, root, fmt.Sprintf("%s|%s|suspect|%s|0|%s", f.id, f.sev, f.rel, ev))
				fps[res.Findings[0].Fingerprint] = true
			}
			if len(fps) != 2 {
				t.Errorf("fingerprints should differ by reason: %v", fps)
			}
		})
	}
	t.Run("exactly 1MiB is read", func(t *testing.T) {
		root := t.TempDir()
		body := `{"scripts":{"postinstall":"node"}}`
		write(t, root, "package.json", body+strings.Repeat(" ", 1<<20-len(body)))
		expectFindings(t, root, "AR-005|low|suspect|package.json|0|postinstall: node")
	})
	t.Run("wrong top-level shape", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "package.json", `[1,2]`)
		expectFindings(t, root, "AR-005|low|suspect|package.json|0|"+ev)
	})
	t.Run("symlink", func(t *testing.T) {
		outside, root := t.TempDir(), t.TempDir()
		write(t, outside, "real.json", `{"scripts":{"postinstall":"node"}}`)
		if err := os.Symlink(filepath.Join(outside, "real.json"), filepath.Join(root, "package.json")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		res := expectFindings(t, root, "AR-005|low|suspect|package.json|0|"+ev)
		// A different reason gives a different fingerprint than a broken file.
		other := t.TempDir()
		write(t, other, "package.json", `{`)
		if res.Findings[0].Fingerprint == run(t, other).Findings[0].Fingerprint {
			t.Error("symlink and unreadable share a fingerprint")
		}
	})
}

func TestAutorunDoesNotFollowSymlink(t *testing.T) {
	outside, root := t.TempDir(), t.TempDir()
	write(t, outside, "tasks.json", `{"tasks":[{"label":"LEAK-LABEL","command":"LEAK-COMMAND","runOptions":{"runOn":"folderOpen"}}]}`)
	write(t, outside, "dir/tasks.json", `{"tasks":[{"label":"LEAK-LABEL","command":"LEAK-COMMAND","runOptions":{"runOn":"folderOpen"}}]}`)
	if err := os.MkdirAll(filepath.Join(root, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "tasks.json"), filepath.Join(root, ".vscode", "tasks.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "dir"), filepath.Join(root, "sub")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	res := run(t, root)
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "LEAK") {
		t.Fatalf("followed a symlink: %s", b)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "AR-001" || res.Findings[0].Confidence != finding.Suspect {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestAutorunMasksSecrets(t *testing.T) {
	const (
		envSecret = "ENVSECRET" + "-9f8e7d6c5b4a"
		hdrSecret = "HEADER" + "SECRET-1a2b3c4d5e6f"
		urlPass   = "hunter2pass"
	)
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"srv":{
		"command":"npx",
		"args":["-y","pkg","--token=`+fakeToken+`","--token","`+fakeToken+`"],
		"env":{"API_KEY":"`+envSecret+`"},
		"headers":{"Authorization":"Bearer `+hdrSecret+`"}}}}`)
	write(t, root, ".devcontainer/devcontainer.json", `{"initializeCommand":"curl -H 'Authorization: Bearer `+fakeToken+`' https://user:`+urlPass+`@example.com/x"}`)
	expectFindings(t, root,
		`AR-004|medium|suspect|.mcp.json|0|srv: {"command":"npx","args":["-y","pkg","--token=****","--token","****"],"env":{"API_KEY":"****"},"headers":{"Authorization":"****"}}`,
		"AR-002|high|certain|.devcontainer/devcontainer.json|0|initializeCommand: curl -H 'Authorization: Bearer ****' https://user:****@example.com/x",
	)
}

func TestAutorunSanitizes(t *testing.T) {
	bad := "a\u202eb\x1b[31m\u200bc\u0085d\ne\rf`g\u2028h"
	long := strings.Repeat("ab ", 600)
	root := t.TempDir()
	lbl, _ := json.Marshal(bad + long)
	cmd, _ := json.Marshal(bad + long)
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":`+string(lbl)+`,"command":`+string(cmd)+`,"runOptions":{"runOn":"folderOpen"}}]}`)
	write(t, root, ".devcontainer/devcontainer.json", `{"postStartCommand":`+string(cmd)+`}`)
	write(t, root, ".mcp.json", `{"mcpServers":{`+string(lbl)+`:{"command":`+string(cmd)+`}}}`)
	write(t, root, ".claude/settings.json", `{"hooks":{`+string(lbl)+`:[{"hooks":[{"type":"command","command":`+string(cmd)+`}]}]}}`)
	write(t, root, "package.json", `{"scripts":{"postinstall":`+string(cmd)+`}}`)
	res := run(t, root)
	if len(res.Findings) != 5 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		for _, s := range []string{f.Evidence, f.Title, f.Location} {
			for _, r := range s {
				if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || unicode.In(r, unicode.Zl, unicode.Zp) || r == '`' {
					t.Errorf("%s: forbidden rune %U in %q", f.ID, r, s)
				}
			}
		}
		i := strings.Index(f.Evidence, ": ")
		if i < 0 {
			t.Fatalf("evidence %q", f.Evidence)
		}
		item, command := []rune(f.Evidence[:i]), []rune(f.Evidence[i+2:])
		if len(item) > 1000+len([]rune(cutMarker)) || len(command) > 1000+len([]rune(cutMarker)) {
			t.Errorf("%s: item %d / command %d runes", f.ID, len(item), len(command))
		}
		if f.ID == "AR-005" || f.ID == "AR-003" {
			continue
		}
		if !strings.HasPrefix(f.Evidence, "ab") {
			t.Errorf("%s: format characters should vanish and leave 'ab...': %q", f.ID, f.Evidence)
		}
	}
}

func TestAutorunNeverRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	m, _ := json.Marshal("echo x > " + marker)
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","command":`+string(m)+`,"runOptions":{"runOn":"folderOpen"}}]}`)
	write(t, root, ".devcontainer/devcontainer.json", `{"initializeCommand":`+string(m)+`,"postCreateCommand":`+string(m)+`}`)
	write(t, root, ".mcp.json", `{"mcpServers":{"a":{"command":`+string(m)+`}}}`)
	write(t, root, ".cursor/mcp.json", `{"mcpServers":{"a":{"command":`+string(m)+`}}}`)
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":`+string(m)+`}]}]}}`)
	write(t, root, "package.json", `{"scripts":{"preinstall":`+string(m)+`,"postinstall":`+string(m)+`,"install":`+string(m)+`,"prepare":`+string(m)+`}}`)
	if n := len(run(t, root).Findings); n != 10 {
		t.Fatalf("findings = %d", n)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a command from the scanned repo was executed")
	}
}

func TestAutorunFingerprintStable(t *testing.T) {
	tasks := func(prefix, cmd string) string {
		return prefix + `{"tasks":[{"label":"dev","command":"` + cmd + `","runOptions":{"runOn":"folderOpen"}}]}`
	}
	fp := func(content string) string {
		root := t.TempDir()
		write(t, root, ".vscode/tasks.json", content)
		res := run(t, root)
		if len(res.Findings) != 1 {
			t.Fatalf("findings = %d", len(res.Findings))
		}
		return res.Findings[0].Fingerprint
	}
	base := fp(tasks("", "node a.js"))
	if got := fp(tasks("// c1\n// c2\n\n\n", "node a.js")); got != base {
		t.Errorf("added lines changed the fingerprint: %s vs %s", got, base)
	}
	if got := fp(tasks("", "node b.js")); got == base {
		t.Error("a changed command kept the fingerprint")
	}
}

func TestExplainFilesEmbedded(t *testing.T) {
	for _, id := range []string{"AR-001", "AR-002", "AR-003", "AR-004", "AR-005"} {
		b, err := fs.ReadFile(aidefensekit.Data, "explain/"+id+".md")
		if err != nil || len(strings.TrimSpace(string(b))) == 0 {
			t.Errorf("explain/%s.md: %v", id, err)
			continue
		}
		for _, banned := range []string{"열면 바로 실행됩니다", "안전합니다"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("explain/%s.md contains %q", id, banned)
			}
		}
		if !strings.Contains(string(b), "일반 텍스트 편집기") || !strings.Contains(string(b), "****") {
			t.Errorf("explain/%s.md lacks the note about masked text", id)
		}
		if id == "AR-001" && !strings.Contains(string(b), "신뢰하거나 자동 작업을 허용하기 전에 명령을 확인하세요") {
			t.Error("AR-001 lacks the VS Code guidance sentence")
		}
	}
}
