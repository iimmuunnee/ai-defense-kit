package secrets

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// repoWithIgnoredEnv makes a repository whose .gitignore lists .env and whose
// .env holds a key but was never committed.
func repoWithIgnoredEnv(t *testing.T) string {
	t.Helper()
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, ".gitignore", ".env\n")
	git(t, root, "add", ".gitignore")
	git(t, root, "commit", "-q", "-m", "ignore env")
	write(t, root, ".env", configLine(fakeKey(t)))
	return root
}

func onlyFinding(t *testing.T, res checker.Result) finding.Finding {
	t.Helper()
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	return res.Findings[0]
}

func TestIgnoredNeverCommittedFileIsLocal(t *testing.T) {
	root := repoWithIgnoredEnv(t)
	f := onlyFinding(t, run(t, root))
	if f.Kind != "secret-local" || f.Severity != finding.Info {
		t.Fatalf("Kind/Severity = %q/%v, want secret-local/Info", f.Kind, f.Severity)
	}
	if f.Location != ".env" || !strings.Contains(f.Title, "git이 무시하는 파일") {
		t.Errorf("Location/Title = %q/%q", f.Location, f.Title)
	}
	cur := New(aidefensekit.Data).(secretsChecker).explain("secret-current.md")
	if f.ExplainKo == "" || f.ExplainKo == cur {
		t.Errorf("secret-local needs its own explanation, got %q", f.ExplainKo)
	}
	if strings.Contains(f.Evidence+f.Title+f.Fix+f.ExplainKo, fakeKey(t)) {
		t.Errorf("raw key leaked: %+v", f)
	}
	// The identity of the finding does not change, so an .adkignore entry
	// written for the old high finding still matches.
	if want := finding.MakeMaskedFingerprint(f.ID, f.Location, f.Evidence, 0); f.Fingerprint != want {
		t.Errorf("Fingerprint = %s, want %s", f.Fingerprint, want)
	}
}

func TestIgnoredFileCommittedBeforeStaysHigh(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, ".env", configLine(fakeKey(t)))
	git(t, root, "add", ".env")
	git(t, root, "commit", "-q", "-m", "add env")
	write(t, root, ".gitignore", ".env\n")
	git(t, root, "rm", "-q", "--cached", ".env")
	git(t, root, "add", ".gitignore")
	git(t, root, "commit", "-q", "-m", "stop tracking env")

	f := onlyFinding(t, run(t, root))
	if f.Kind != "secret-current" || f.Severity != finding.High {
		t.Errorf("Kind/Severity = %q/%v, want secret-current/High: the key is in history", f.Kind, f.Severity)
	}
}

func TestUntrackedNotIgnoredFileStaysHigh(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "config.py", configLine(fakeKey(t)))

	f := onlyFinding(t, run(t, root))
	if f.Kind != "secret-current" || f.Severity != finding.High {
		t.Errorf("Kind/Severity = %q/%v, want secret-current/High: the next git add takes it", f.Kind, f.Severity)
	}
}

func TestUntrustedIgnoredFileStaysHigh(t *testing.T) {
	root := repoWithIgnoredEnv(t)
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: root, Untrusted: true})
	if err != nil {
		t.Fatal(err)
	}
	f := onlyFinding(t, res)
	if f.Kind != "secret-current" || f.Severity != finding.High {
		t.Errorf("Kind/Severity = %q/%v, want secret-current/High under --untrusted", f.Kind, f.Severity)
	}
}

func TestIgnoredFileInSubfolderScanIsLocal(t *testing.T) {
	root := repoWithIgnoredEnv(t)
	write(t, root, "app/.env", configLine(fakeKey(t)))
	f := onlyFinding(t, run(t, filepath.Join(root, "app")))
	if f.Kind != "secret-local" || f.Location != ".env" {
		t.Errorf("Kind/Location = %q/%q, want secret-local/.env", f.Kind, f.Location)
	}
}
