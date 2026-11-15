package secrets

import (
	"fmt"
	"strings"
	"testing"
)

// filler is text past the size limit with nothing gitleaks looks for.
func filler() string {
	return strings.Repeat("x = 0\n", historyMaxSize/6+100)
}

// 과거 기록의 아주 큰 변경(5MB 초과)은 점검하지 않고 경고로 알린다. 파일 하나가
// 5분 제한을 넘기게 만들 수 있기 때문이다. 작은 변경은 그대로 점검한다.
func TestHistorySkipsLargePatchesWithWarning(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	key := configLine(fakeKey(t))
	write(t, root, "big.txt", filler()+key)
	write(t, root, "small.py", key)
	write(t, root, "node_modules/pkg/big.js", filler()+key)
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "c1")
	git(t, root, "rm", "-q", "-r", "big.txt", "small.py", "node_modules")
	git(t, root, "commit", "-q", "-m", "c2")

	res := run(t, root)
	if len(res.Findings) != 1 || res.Findings[0].Kind != "secret-history" || res.Findings[0].Location != "small.py" {
		t.Fatalf("findings = %+v, want the history secret at small.py only", res.Findings)
	}
	var warn string
	for _, w := range res.Warnings {
		if strings.Contains(w, "5MB") {
			warn = w
		}
	}
	if warn == "" {
		t.Fatalf("no warning about skipped large changes: %v", res.Warnings)
	}
	if !strings.Contains(warn, "big.txt") {
		t.Errorf("warning does not name the skipped file: %q", warn)
	}
	// A folder that is never checked is not something the user missed.
	if strings.Contains(warn, "node_modules") {
		t.Errorf("warning names a skipped dependency folder: %q", warn)
	}
}

func TestSkippedLargeWarningListsFewPaths(t *testing.T) {
	var paths []string
	for i := range 7 {
		paths = append(paths, fmt.Sprintf("docs/p%d.html", i))
	}
	w := skippedLargeWarning(paths)
	for _, want := range []string{"7개", "docs/p0.html", "docs/p4.html", "외 2개"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q lacks %q", w, want)
		}
	}
	if strings.Contains(w, "docs/p5.html") {
		t.Errorf("warning lists more than five paths: %q", w)
	}
	if got := skippedLargeWarning([]string{"a\x1b[31m.txt"}); strings.ContainsRune(got, '\x1b') {
		t.Errorf("control characters kept: %q", got)
	}
}
