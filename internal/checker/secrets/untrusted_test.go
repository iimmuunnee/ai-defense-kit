package secrets

import (
	"context"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

func runUntrusted(t *testing.T, root string) checker.Result {
	t.Helper()
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: root, Untrusted: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func kinds(res checker.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Kind)
	}
	return out
}

const allowedLine = "k = \"" + fakeToken + "\" // gitleaks:allow\n"

func TestSecretsUntrustedFindsAllowedLineInCurrentFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.js", allowedLine)
	if res := run(t, root); len(res.Findings) != 0 {
		t.Errorf("control: without --untrusted gitleaks:allow hides the line, got %v", kinds(res))
	}
	if res := runUntrusted(t, root); len(res.Findings) != 1 || res.Findings[0].Kind != "secret-current" {
		t.Errorf("untrusted: got %v", kinds(res))
	}
}

func TestSecretsUntrustedFindsAllowedLineInHistory(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "config.js", allowedLine)
	git(t, root, "add", ".")
	git(t, root, "commit", "-qm", "one")
	write(t, root, "config.js", "k = 1\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-qm", "two")
	if res := run(t, root); len(res.Findings) != 0 {
		t.Errorf("control: without --untrusted gitleaks:allow hides the line, got %v", kinds(res))
	}
	if res := runUntrusted(t, root); len(res.Findings) != 1 || res.Findings[0].Kind != "secret-history" {
		t.Errorf("untrusted: got %v", kinds(res))
	}
}

// The library does not read these two files, with or without the flag.
func TestSecretsConfigFilesHideNothing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.js", "k = \""+fakeToken+"\"\n")
	write(t, root, ".gitleaks.toml", "[allowlist]\npaths = ['''config\\.js''']\n")
	write(t, root, ".gitleaksignore", "config.js:github-pat:1\n")
	if res := run(t, root); len(res.Findings) != 1 {
		t.Errorf("got %v", kinds(res))
	}
	if res := runUntrusted(t, root); len(res.Findings) != 1 {
		t.Errorf("untrusted: got %v", kinds(res))
	}
}
