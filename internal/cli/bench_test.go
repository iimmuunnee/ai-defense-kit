package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 재현 세트: 정답표가 있는 예제 앱을 실제 점검 순서대로 돌려
// 정답 중 찾은 것, 놓친 것, 정답표 밖 결과(오탐 후보)를 센다.
//
// 결과는 testdata/bench/cases-result.json과 비교해 하나라도 바뀌면 실패한다.
// 의도한 변경이면 ADK_BENCH_UPDATE=1로 다시 돌려 기준을 갱신한다.
// ADK_BENCH_MD=<경로>를 주면 Markdown 요약을 그 파일에 쓴다.
// 의존성 결과는 가짜 OSV 자료에서 나오므로 세지 않는다.

const benchResult = "../../testdata/bench/cases-result.json"

type benchCase struct {
	name string
	dir  string
	args []string
}

var benchCases = []benchCase{
	{"sample-app", sampleApp, nil},
	{"fake-assignment", fakeAssignment, []string{"--untrusted"}},
	{"clean-app", "../../testdata/bench/cases/clean-app", nil},
	{"tricky-app", "../../testdata/bench/cases/tricky-app", nil},
}

type answer struct {
	Location string `json:"location"`
	ID       string `json:"id"` // "SECRET-*"처럼 끝이 *이면 앞부분만 맞으면 됨
}

func (a answer) matches(id, loc string) bool {
	if a.Location != loc {
		return false
	}
	if p, ok := strings.CutSuffix(a.ID, "*"); ok {
		return strings.HasPrefix(id, p)
	}
	return a.ID == id
}

// caseResult is what one case produced. Items are "ID @ location".
type caseResult struct {
	Expected int      `json:"expected"`
	Found    []string `json:"found"`
	Missed   []string `json:"missed"`
	Extra    []string `json:"extra"`
}

func runBenchCase(t *testing.T, c benchCase) caseResult {
	t.Helper()
	b, err := os.ReadFile("../../testdata/bench/answers/" + c.name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Expected []answer `json:"expected"`
	}
	if err := json.Unmarshal(b, &key); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	args := append([]string{"scan", c.dir, "--format", "json", "--out", tmp, "--offline", "--fail-on", "none"}, c.args...)
	if code, _, se := runCLI(t, args...); code != 0 {
		t.Fatalf("%s: exit %d: %s", c.name, code, se)
	}
	rb, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Source   string `json:"source"`
			Location string `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(rb, &rep); err != nil {
		t.Fatal(err)
	}

	res := caseResult{Expected: len(key.Expected), Found: []string{}, Missed: []string{}, Extra: []string{}}
	hit := make([]bool, len(key.Expected))
	for _, f := range rep.Findings {
		if f.Source == "deps" {
			continue
		}
		matched := false
		for i, a := range key.Expected {
			if !hit[i] && a.matches(f.ID, f.Location) {
				hit[i], matched = true, true
				break
			}
		}
		if !matched {
			res.Extra = append(res.Extra, f.ID+" @ "+f.Location)
		}
	}
	for i, a := range key.Expected {
		item := a.ID + " @ " + a.Location
		if hit[i] {
			res.Found = append(res.Found, item)
		} else {
			res.Missed = append(res.Missed, item)
		}
	}
	sort.Strings(res.Found)
	sort.Strings(res.Missed)
	sort.Strings(res.Extra)
	return res
}

func TestBenchCases(t *testing.T) {
	useFakeDeps(t)
	got := map[string]caseResult{}
	for _, c := range benchCases {
		got[c.name] = runBenchCase(t, c)
	}

	if out := os.Getenv("ADK_BENCH_MD"); out != "" {
		if err := os.WriteFile(out, []byte(benchMarkdown(got)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	gotJSON = append(gotJSON, '\n')
	if os.Getenv("ADK_BENCH_UPDATE") == "1" {
		if err := os.WriteFile(benchResult, gotJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(benchResult)
	if err != nil {
		t.Fatalf("기준 파일을 읽지 못함 (ADK_BENCH_UPDATE=1로 만들 수 있음): %v", err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != string(gotJSON) {
		t.Errorf("재현 세트 결과가 기준과 다름. 의도한 변경이면 ADK_BENCH_UPDATE=1로 기준을 갱신하세요.\n기준:\n%s\n이번:\n%s",
			want, gotJSON)
	}
}

func benchMarkdown(got map[string]caseResult) string {
	var b strings.Builder
	b.WriteString("| 예제 | 정답 | 찾음 | 놓침 | 정답표 밖 결과 |\n|---|---|---|---|---|\n")
	for _, c := range benchCases {
		r := got[c.name]
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", c.name, r.Expected, len(r.Found), len(r.Missed), len(r.Extra))
	}
	for _, c := range benchCases {
		r := got[c.name]
		if len(r.Missed)+len(r.Extra) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n**%s**\n\n", c.name)
		for _, m := range r.Missed {
			b.WriteString("- 놓침: `" + m + "`\n")
		}
		for _, e := range r.Extra {
			b.WriteString("- 정답표 밖: `" + e + "`\n")
		}
	}
	return b.String()
}
