package cli

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// copyTreeWithoutGit copies the repository files into dst and leaves .git out,
// so the scan reads current files only, never git history, and never depends on
// where the checkout lives.
func copyTreeWithoutGit(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		// A worktree has a .git file pointing at the real repository; copying it
		// would let the scan read git history after all.
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestSelfScanHasNoUnexplainedFindings scans adk's own repository offline,
// current files only, and expects every finding to be listed in .adkignore with
// a reason. A new secret-shaped literal in a test or fixture fails here.
func TestSelfScanHasNoUnexplainedFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("저장소 전체 자기 점검은 느려 -short에서 건너뜁니다")
	}
	work := t.TempDir()
	copyTreeWithoutGit(t, filepath.Join("..", ".."), work)
	out := t.TempDir()
	code, _, se := runCLI(t, "scan", work, "--offline", "--format", "json", "--out", out, "--fail-on", "none")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(out, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Location string `json:"location"`
			Line     int    `json:"line"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		t.Errorf("설명 없는 결과: %s %s:%d (값이 아니면 .adkignore에 이유와 함께 적고, 시험 안의 키 모양 문자열이면 실행 중에 조립하세요)", f.ID, f.Location, f.Line)
	}
}
