package autorun

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

func TestAR006Findings(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		".adkignore",
		"osv-scanner.toml",
		"services/api/osv-scanner.toml",
		"dist/osv-scanner.toml", // osv-scanner reads these folders, which this walk skips otherwise
		"node_modules/x/osv-scanner.toml",
		".devcontainer/dist/osv-scanner.toml",
	} {
		write(t, root, rel, "# anything\n")
	}
	want := []string{
		"AR-006|low|certain|.adkignore|0|.adkignore",
		"AR-006|low|certain|osv-scanner.toml|0|osv-scanner.toml",
		"AR-006|low|certain|services/api/osv-scanner.toml|0|osv-scanner.toml",
		"AR-006|low|certain|dist/osv-scanner.toml|0|osv-scanner.toml",
		"AR-006|low|certain|node_modules/x/osv-scanner.toml|0|osv-scanner.toml",
		"AR-006|low|certain|.devcontainer/dist/osv-scanner.toml|0|osv-scanner.toml",
	}
	expectFindings(t, root, want...)
}

// These files were tried and change no result, or are read from somewhere else.
func TestAR006LeavesOtherFilesAlone(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"sub/.adkignore",
		"dist/.adkignore",
		".osv-scanner.toml",
		"sub/.osv-scanner.toml",
		".gitleaksignore",
		".gitleaks.toml",
		"gitleaks.toml",
		".git/osv-scanner.toml",
		"sub/.git/osv-scanner.toml",
		"dist/.git/osv-scanner.toml",
		"my-osv-scanner.toml",
	} {
		write(t, root, rel, "# anything\n")
	}
	if err := os.MkdirAll(filepath.Join(root, "osv-scanner.toml"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectFindings(t, root)
}

func TestAR006NothingToFind(t *testing.T) {
	expectFindings(t, t.TempDir())
}

func TestAR006UntrustedSaysTheFileWasNotUsed(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".adkignore", "x\n")
	write(t, root, "sub/osv-scanner.toml", "x\n")
	plain := run(t, root)
	res, err := New(testData).Run(context.Background(), checker.Target{Root: root, Untrusted: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"AR-006|low|certain|.adkignore|0|.adkignore: --untrusted로 이 파일을 쓰지 않았습니다.",
		"AR-006|low|certain|sub/osv-scanner.toml|0|osv-scanner.toml: --untrusted로 이 파일을 쓰지 않았습니다.",
	}
	got := summarize(res.Findings)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %v", got)
	}
	// A fingerprint in a list made with or without the flag must keep matching.
	if len(plain.Findings) != 2 || plain.Findings[0].Fingerprint != res.Findings[0].Fingerprint || plain.Findings[1].Fingerprint != res.Findings[1].Fingerprint {
		t.Errorf("fingerprints differ: %v %v", plain.Findings, res.Findings)
	}
}

func TestAR006FixedTextAndExplanation(t *testing.T) {
	root := t.TempDir()
	write(t, root, "osv-scanner.toml", "[[IgnoredVulns]]\nid = \"`](https://evil.example)\"\n")
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings: %v", summarize(res.Findings))
	}
	f := res.Findings[0]
	if f.Title != "결과를 숨길 수 있는 설정 파일" || f.Evidence != "osv-scanner.toml" || f.Kind != "AR-006" {
		t.Errorf("%+v", f)
	}
	if !strings.Contains(f.ExplainKo, "--untrusted") {
		t.Errorf("explanation: %q", f.ExplainKo)
	}
	if len(f.References) != 0 {
		t.Errorf("references: %v", f.References)
	}
}

// A link is reported without being followed: osv-scanner would read through it.
func TestAR006ReportsALink(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), filepath.Join(root, "osv-scanner.toml")); err != nil {
		t.Skip("symlinks not available")
	}
	expectFindings(t, root, "AR-006|low|certain|osv-scanner.toml|0|osv-scanner.toml")
}

// lateCancel reports cancellation from its n-th question on.
type lateCancel struct {
	context.Context
	n int
}

func (c *lateCancel) Err() error {
	if c.n--; c.n < 0 {
		return context.Canceled
	}
	return nil
}

// dist comes last in the walk and is left only through findOSVConfigs, so nothing
// after it would notice: the error can only come from the walk inside it.
func TestAR006WalkOfASkippedFolderStopsWhenCancelled(t *testing.T) {
	root := t.TempDir()
	write(t, root, "dist/a/x.txt", "x")
	write(t, root, "dist/osv-scanner.toml", "x")
	// Asked once by the walk at root, once at dist, once entering the inner walk.
	ctx := &lateCancel{Context: context.Background(), n: 3}
	res, err := New(testData).Run(ctx, checker.Target{Root: root})
	if err == nil {
		t.Errorf("expected an error, got %v", summarize(res.Findings))
	}
	// Control: given time, the same walk finds the file.
	expectFindings(t, root, "AR-006|low|certain|dist/osv-scanner.toml|0|osv-scanner.toml")
}

func TestAR006WarnsAboutAnUnreadableSkippedFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	root := t.TempDir()
	write(t, root, "dist/sub/osv-scanner.toml", "x")
	sub := filepath.Join(root, "dist", "sub")
	if err := os.Chmod(sub, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sub, 0o755) })
	if _, err := os.ReadDir(sub); err == nil {
		t.Skip("running with permission to read anything")
	}
	res := run(t, root)
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "dist/sub") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

// Only a file the tools would open is reported. Whether .ADKIGNORE is that file
// depends on the file system, which the test asks.
func TestAR006ReportsOnlyFilesThatAreRead(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".ADKIGNORE", "x")
	write(t, root, "sub/OSV-Scanner.TOML", "x")
	_, err := os.Stat(filepath.Join(root, ".adkignore"))
	foldsCase := err == nil
	var want []string
	if foldsCase {
		want = []string{"AR-006|low|certain|.ADKIGNORE|0|.ADKIGNORE", "AR-006|low|certain|sub/OSV-Scanner.TOML|0|OSV-Scanner.TOML"}
	}
	expectFindings(t, root, want...)
}
