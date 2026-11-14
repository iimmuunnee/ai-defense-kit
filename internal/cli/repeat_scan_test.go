package cli

import (
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
)

// runtimeKey makes a high-entropy value at run time from digits and uppercase
// consonants (no word gitleaks would ignore), so no key-shaped string sits in
// the repository.
func runtimeKey(t *testing.T) string {
	t.Helper()
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ0123456789"
	var b strings.Builder
	for range 36 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String()
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeIn(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// repeatRepo builds a repository where one key is spread over several commits
// and files and then removed (history only), and another sits in two current
// files and in history (current wins, repeats get numbered).
func repeatRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	gone, kept := runtimeKey(t), runtimeKey(t)
	line := func(k string) string { return "api_key = \"" + k + "\"\n" }
	gitIn(t, root, "init", "-q")
	writeIn(t, root, "a/config.py", line(gone))
	writeIn(t, root, "b/settings.py", line(gone))
	writeIn(t, root, "app.py", line(kept))
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "commit", "-q", "-m", "c1")
	writeIn(t, root, "c/other.py", "x = 1\n"+line(gone))
	writeIn(t, root, "d/more.py", line(gone)+line(gone))
	writeIn(t, root, "lib/app.py", "# copy\n"+line(kept))
	gitIn(t, root, "add", "-A")
	gitIn(t, root, "commit", "-q", "-m", "c2")
	for _, p := range []string{"a/config.py", "b/settings.py", "c/other.py", "d/more.py"} {
		gitIn(t, root, "rm", "-q", p)
	}
	gitIn(t, root, "commit", "-q", "-m", "c3")
	return root
}

type shownFinding struct {
	Fingerprint, ID, Kind, Location, Evidence string
	Line                                      int
}

func scanFindings(t *testing.T, root string) []shownFinding {
	t.Helper()
	_, stdout, stderr := runCLI(t, "scan", root, "--format", "json", "--fail-on", "none")
	var rep struct {
		Findings []shownFinding
		Checks   []struct{ Name, Status string }
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v: %s\n%s", err, stdout, stderr)
	}
	for _, c := range rep.Checks {
		if c.Status != string(checker.StatusOK) {
			t.Fatalf("check %s ended %s: %s", c.Name, c.Status, stderr)
		}
	}
	return rep.Findings
}

// 같은 저장소를 여러 번 점검하면 결과(지문, 대표 위치, 순서)가 같아야 한다. 무시 목록과
// 기준선은 이것에 기댄다. gitleaks가 과거 기록을 병렬로 읽어 결과 순서가 바뀌므로,
// 동시에 도는 작업 수(GOMAXPROCS)를 바꿔서도 돌린다.
func TestScanTwiceGivesSameResult(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, _ scanOptions) []checker.Checker {
		return []checker.Checker{secrets.New(data)}
	}
	root := repeatRepo(t)

	first := scanFindings(t, root)
	kinds := map[string]int{}
	for _, f := range first {
		kinds[f.Kind]++
	}
	// One history-only key (several places) and two current copies of the other.
	if kinds["secret-history"] != 1 || kinds["secret-current"] != 2 {
		t.Fatalf("unexpected findings, the repository is not exercised: %+v", first)
	}

	procs := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(procs)
	for i, p := range []int{procs, 1, 2, procs} {
		runtime.GOMAXPROCS(p)
		if again := scanFindings(t, root); !slices.Equal(first, again) {
			t.Fatalf("run %d (GOMAXPROCS=%d) differs:\nfirst %+v\nagain %+v", i+2, p, first, again)
		}
	}
}
