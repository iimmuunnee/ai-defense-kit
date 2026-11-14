package secrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 놓침 표: 키 종류 × 놓인 자리마다 가짜 키를 하나씩 심고, 비밀 키 점검이
// 찾는지(found), "의심"으로 찾는지(suspect), 놓치는지(missed)를 잰다.
//
// 키는 시험을 돌릴 때 고정된 씨앗의 난수로 만든다. 저장소에는 키 모양 문자열을
// 두지 않으면서도, 값에 따라 결과가 달라지는 칸(예: 이어붙인 키의 앞 절반이
// 일반 규칙의 무작위성 기준을 넘는지)이 실행마다 흔들리지 않게 하려는 것이다.
// 결과는 testdata/bench/secrets-recall.json과 비교해, 한 칸이라도 바뀌면 실패한다.
// 바뀐 것이 의도한 개선이면 ADK_BENCH_UPDATE=1로 다시 돌려 기준을 갱신한다.
// ADK_BENCH_MD=<경로>를 주면 Markdown 표를 그 파일에 쓴다.

const (
	upperConsonants = "BCDFGHJKLMNPQRSTVWXZ"
	digits          = "0123456789"
	lowerConsonants = "bcdfghjklmnpqrstvwxz"
	recallGolden    = "../../../testdata/bench/secrets-recall.json"
)

// recallRand is reset by buildRecallRepo so every run makes the same values.
var recallRand *rand.Rand

// randFrom returns n characters drawn from alphabet. Vowels are left out of
// the alphabets above so a value cannot spell a gitleaks stopword.
func randFrom(t *testing.T, alphabet string, n int) string {
	t.Helper()
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[recallRand.IntN(len(alphabet))])
	}
	return b.String()
}

type keyKind struct {
	name string // 표에 쓰는 이름
	// line returns a source line (or block) holding a fresh key.
	line func(t *testing.T) string
}

var keyKinds = []keyKind{
	{"aws-access-key-id", func(t *testing.T) string {
		return `aws_access_key_id = "AKIA` + randFrom(t, upperConsonants+"234567", 16) + "\"\n"
	}},
	{"github-pat", func(t *testing.T) string {
		return `token = "ghp_` + randFrom(t, upperConsonants+lowerConsonants+digits, 36) + "\"\n"
	}},
	{"slack-bot-token", func(t *testing.T) string {
		return `slack = "xoxb-` + randFrom(t, digits, 12) + "-" + randFrom(t, digits, 12) + "-" +
			randFrom(t, upperConsonants+lowerConsonants+digits, 24) + "\"\n"
	}},
	{"stripe-test-key", func(t *testing.T) string {
		return `stripe_key = "sk_test_` + randFrom(t, upperConsonants+lowerConsonants+digits, 32) + "\"\n"
	}},
	{"generic-api-key", func(t *testing.T) string {
		return `api_key = "` + randFrom(t, upperConsonants+digits, 36) + "\"\n"
	}},
	{"private-key", func(t *testing.T) string {
		body := randFrom(t, upperConsonants+lowerConsonants+digits, 64)
		return "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n" + body[:32] +
			"\n-----END RSA PRIVATE KEY-----\n"
	}},
}

// placement is one place a key can sit. path gives the file for a key kind.
type placement struct {
	name string
	path func(kind string) string
	// wrap turns the key line into the file's content.
	wrap func(line string) string
	how  string // "current", "untracked", "history-edited", "history-deleted"
}

func plain(line string) string { return line }

var placements = []placement{
	{"코드", func(k string) string { return "src/" + k + "_config.js" }, plain, "current"},
	{"환경 파일", func(k string) string { return "deploy/" + k + "/.env" }, plain, "current"},
	{"주석", func(k string) string { return "src/" + k + "_note.py" }, func(l string) string {
		return "# " + strings.ReplaceAll(strings.TrimSuffix(l, "\n"), "\n", "\n# ") + "\n"
	}, "current"},
	{"문서", func(k string) string { return "docs/" + k + "-setup.md" }, func(l string) string {
		return "# 설정\n\n```\n" + l + "```\n"
	}, "current"},
	{"시험 폴더", func(k string) string { return "tests/" + k + "_fixture.py" }, plain, "current"},
	{"커밋 안 한 파일", func(k string) string { return "scratch/" + k + ".txt" }, plain, "untracked"},
	{"과거 기록(줄 지움)", func(k string) string { return "old/" + k + "_settings.js" }, plain, "history-edited"},
	{"과거 기록(파일 지움)", func(k string) string { return "removed/" + k + "_creds.txt" }, plain, "history-deleted"},
	{"건너뛰는 폴더(node_modules)", func(k string) string { return "node_modules/pkg/" + k + ".js" }, plain, "current"},
	// 아래는 일부러 어렵게 만든 자리다. 놓치는 것이 이 표의 정보다.
	{"문자열 이어붙이기", func(k string) string { return "tricky/" + k + "_concat.js" }, splitLongestRun, "current"},
	{"base64로 감쌈", func(k string) string { return "tricky/" + k + "_b64.js" }, func(l string) string {
		return `payload = "` + base64.StdEncoding.EncodeToString([]byte(l)) + "\"\n"
	}, "current"},
	{"이름 없는 JSON 값", func(k string) string { return "tricky/" + k + "_value.json" }, func(l string) string {
		v, _ := json.Marshal(quotedValue(l))
		return `{"v": ` + string(v) + "}\n"
	}, "current"},
	{"1MB 넘는 파일 끝", func(k string) string { return "big/" + k + "_bundle.js" }, func(l string) string {
		return strings.Repeat("// filler line for size\n", (maxFileSize/24)+1024) + l
	}, "current"},
}

// splitLongestRun splits the longest run of letters and digits in s in two
// with `" + "`, as if the value were built by joining two strings.
func splitLongestRun(s string) string {
	bestStart, bestLen, start := 0, 0, -1
	isAlnum := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isAlnum(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start > bestLen {
			bestStart, bestLen = start, i-start
		}
		start = -1
	}
	mid := bestStart + bestLen/2
	return s[:mid] + `" + "` + s[mid:]
}

// quotedValue returns what sits between the first and last double quote of
// line, or the whole line when it has no quotes (a PEM block).
func quotedValue(line string) string {
	i, j := strings.Index(line, `"`), strings.LastIndex(line, `"`)
	if i < 0 || j <= i {
		return line
	}
	return line[i+1 : j]
}

// buildRecallRepo writes every key kind into every placement and returns the
// repository root.
func buildRecallRepo(t *testing.T) string {
	t.Helper()
	recallRand = rand.New(rand.NewChaCha8([32]byte{'a', 'd', 'k', '-', 'b', 'e', 'n', 'c', 'h'}))
	root := t.TempDir()
	git(t, root, "init", "-q")
	// 1st commit: what later disappears from the working tree.
	for _, p := range placements {
		if p.how != "history-edited" && p.how != "history-deleted" {
			continue
		}
		for _, k := range keyKinds {
			write(t, root, p.path(k.name), "// before\n"+p.wrap(k.line(t)))
		}
	}
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "first")
	// 2nd commit: remove those keys and add the current ones.
	for _, p := range placements {
		for _, k := range keyKinds {
			rel := p.path(k.name)
			switch p.how {
			case "history-edited":
				write(t, root, rel, "// before\n// 값은 환경 변수에서 읽음\n")
			case "history-deleted":
				git(t, root, "rm", "-q", filepath.ToSlash(rel))
			case "current":
				write(t, root, rel, p.wrap(k.line(t)))
			}
		}
	}
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "second")
	// Untracked files are written after the last commit.
	for _, p := range placements {
		if p.how != "untracked" {
			continue
		}
		for _, k := range keyKinds {
			write(t, root, p.path(k.name), p.wrap(k.line(t)))
		}
	}
	return root
}

const (
	cellFound   = "found"
	cellSuspect = "suspect"
	cellMissed  = "missed"
)

func TestSecretsRecallTable(t *testing.T) {
	needGit(t)
	root := buildRecallRepo(t)
	res := run(t, root)

	byPath := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byPath[f.Location] = f
	}
	got := map[string]string{}
	for _, p := range placements {
		for _, k := range keyKinds {
			cell := cellMissed
			if f, ok := byPath[p.path(k.name)]; ok {
				t.Logf("%s / %s: %s, 과거 기록=%v", p.name, k.name, f.ID, strings.Contains(f.Evidence, "(커밋"))
				cell = cellFound
				if f.Confidence == finding.Suspect {
					cell = cellSuspect
				}
			}
			got[p.name+" / "+k.name] = cell
		}
	}

	if out := os.Getenv("ADK_BENCH_MD"); out != "" {
		if err := os.WriteFile(out, []byte(recallMarkdown(got)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("ADK_BENCH_UPDATE") == "1" {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(recallGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recallGolden, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	b, err := os.ReadFile(recallGolden)
	if err != nil {
		t.Fatalf("기준 파일을 읽지 못함 (ADK_BENCH_UPDATE=1로 만들 수 있음): %v", err)
	}
	var want map[string]string
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	var diffs []string
	for cell, w := range want {
		if got[cell] != w {
			diffs = append(diffs, fmt.Sprintf("%s: 기준 %s, 이번 %s", cell, w, got[cell]))
		}
	}
	for cell := range got {
		if _, ok := want[cell]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: 기준에 없는 칸", cell))
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("놓침 표가 기준과 다름. 의도한 변경이면 ADK_BENCH_UPDATE=1로 기준을 갱신하세요.\n%s",
			strings.Join(diffs, "\n"))
	}
}

func recallMarkdown(got map[string]string) string {
	mark := map[string]string{cellFound: "찾음", cellSuspect: "의심", cellMissed: "놓침"}
	var b strings.Builder
	b.WriteString("| 놓인 자리 |")
	for _, k := range keyKinds {
		b.WriteString(" " + k.name + " |")
	}
	b.WriteString("\n|---|")
	for range keyKinds {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, p := range placements {
		b.WriteString("| " + p.name + " |")
		for _, k := range keyKinds {
			b.WriteString(" " + mark[got[p.name+" / "+k.name]] + " |")
		}
		b.WriteString("\n")
	}
	return b.String()
}
