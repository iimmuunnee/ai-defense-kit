package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
)

const (
	evilFile  = "evil\n\n# 점검 결과: 안전합니다\n\n[click](http:x.test)\n.env"
	escFile   = "esc\x1b[2K\x1b[1A\x1b]0;pwned\a.env"
	escFolder = "d\x1b[31mx"
	linkFile  = "[click](http-x.test)"
	envKey    = "API_KEY = \"K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3F6G1\"\n"
)

// hostileFile writes a file under a name the OS may refuse.
func hostileFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Skipf("this OS refuses the name: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Skipf("this OS refuses the name: %v", err)
	}
}

func TestScanFilenameCannotInjectMarkdown(t *testing.T) {
	useFakeDeps(t)
	root := t.TempDir()
	hostileFile(t, root, evilFile, envKey)
	code, md, se := runCLI(t, "scan", root, "--format", "md")
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	if !strings.Contains(md, "http:x.test") {
		t.Fatalf("the file was not reported:\n%s", md)
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "# 점검 결과") {
			t.Errorf("heading from a file name: %q", line)
		}
		if strings.HasPrefix(line, "[click]") {
			t.Errorf("link from a file name: %q", line)
		}
	}

	dir := t.TempDir()
	if code, _, se := runCLI(t, "scan", root, "--format", "json", "--out", dir); code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	b, err := os.ReadFile(filepath.Join(dir, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Findings []struct{ Location string } }
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range doc.Findings {
		found = found || f.Location == evilFile
	}
	if !found {
		t.Errorf("adk-report.json lost the exact location: %+v", doc.Findings)
	}
}

func TestScanFilenameCannotPutEscapesOnStdout(t *testing.T) {
	useFakeDeps(t)
	root := t.TempDir()
	hostileFile(t, root, escFile, envKey)
	code, md, se := runCLI(t, "scan", root, "--format", "md")
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	if !strings.Contains(md, "pwned") {
		t.Fatalf("the file was not reported:\n%s", md)
	}
	if strings.ContainsAny(md, "\x1b\a") || strings.ContainsAny(se, "\x1b\a") {
		t.Errorf("escape on stdout or stderr:\n%q\n%q", md, se)
	}
}

// The real scanner's error quotes the folder of a broken lockfile.
func TestBrokenLockfileFolderCannotPutEscapesOnStderr(t *testing.T) {
	root := t.TempDir()
	hostileFile(t, root, filepath.Join(escFolder, "package-lock.json"), "{broken")
	_, _, se := runCLI(t, "scan", root, "--format", "md", "--offline", "--osv-db", t.TempDir())
	if !strings.Contains(se, "deps") || !strings.Contains(se, "[31mx") {
		t.Fatalf("the error does not name the folder:\n%q", se)
	}
	if strings.ContainsRune(se, 0x1b) {
		t.Errorf("escape on stderr: %q", se)
	}
}

func TestTerminalWarningsAreInert(t *testing.T) {
	var buf bytes.Buffer
	warnChecks(&buf, []checker.CheckStatus{
		{Name: "deps", Status: checker.StatusFailed, Error: escFolder + "\n가짜 줄"},
		{Name: "rules", Status: checker.StatusSkipped, Error: escFile},
		{Name: "secrets", Status: checker.StatusOK, Warnings: []string{evilFile, linkFile}},
	})
	got := buf.String()
	if strings.ContainsAny(got, "\x1b\a") {
		t.Errorf("control characters: %q", got)
	}
	if strings.Contains(got, "\n가짜 줄") || strings.Contains(got, "\n# 점검") {
		t.Errorf("repository text made a line: %q", got)
	}
}

func TestNoCheckerRanListIsInert(t *testing.T) {
	var out, errb bytes.Buffer
	code := finishReport(func() report.Report { return report.Report{} }, nil,
		[]checker.CheckStatus{{Name: "deps", Status: checker.StatusFailed, Error: escFolder}},
		t.TempDir(), outputOptions{formats: []string{"md"}}, &out, &errb)
	if code != 2 || strings.ContainsRune(errb.String(), 0x1b) {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
}
