package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func markdownOf(t *testing.T, r Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func sameTextFinding(loc, fp, evidence string) finding.Finding {
	return finding.Finding{ID: "DV-202", Severity: finding.Medium, Confidence: finding.Certain, Location: loc, Fingerprint: fp, Evidence: evidence,
		Title: "지갑 저장소가 있음", ExplainKo: "긴 설명입니다.\n\n왜 확인해야 하나요?\n- 이유", Fix: "1. 고치는 법",
		References: []string{"https://example.test/ref"}, Mappings: []finding.Mapping{{ID: "ISMSP-2.10.4", ReviewStatus: "draft"}}}
}

// Findings of one number that share their text show the text once, with the
// findings listed under it.
func TestMarkdownSaysSharedTextOnce(t *testing.T) {
	r := Report{Kind: KindDevice, NoIgnoreAdvice: true, Findings: []finding.Finding{
		sameTextFinding("~/b/Profile 1", "2222222222222222", "MetaMask (Chrome) 둘"),
		{ID: "DV-204", Severity: finding.Medium, Confidence: finding.Certain, Location: "~/a/id.json", Title: "키 파일", ExplainKo: "다른 설명", Fix: "다른 수정"},
		sameTextFinding("~/b/Default", "1111111111111111", "MetaMask (Chrome) 하나"),
		sameTextFinding("~/c/Default", "3333333333333333", ""),
	}}
	out := markdownOf(t, r)
	for _, once := range []string{"### [보통] 지갑 저장소가 있음", "- 번호: DV-202", "긴 설명입니다.", "왜 확인해야 하나요?", "1. 고치는 법", "https://example.test/ref", "ISMSP-2.10.4"} {
		if n := strings.Count(out, once); n != 1 {
			t.Errorf("%q is in the report %d times, want 1:\n%s", once, n, out)
		}
	}
	if !strings.Contains(out, "### [보통] 지갑 저장소가 있음 (3건)") || !strings.Contains(out, "**해당 결과 3건**") {
		t.Fatalf("the count is not shown:\n%s", out)
	}
	// Every finding keeps its place, judgement, fingerprint and evidence,
	// in the order of the sorted list, below the shared text.
	list := out[strings.Index(out, "**해당 결과 3건**"):]
	last := -1
	for _, want := range []string{
		"1. 위치: `~/b/Default`", "   - 지문: 1111111111111111", "   - 근거: `MetaMask (Chrome) 하나`",
		"2. 위치: `~/b/Profile 1`", "   - 지문: 2222222222222222", "   - 근거: `MetaMask (Chrome) 둘`",
		"3. 위치: `~/c/Default`", "   - 지문: 3333333333333333",
	} {
		i := strings.Index(list, want)
		if i < 0 || i < last {
			t.Errorf("%q missing or out of order:\n%s", want, list)
		}
		last = i
	}
	if n := strings.Count(out, "   - 판단: 확실"); n != 3 {
		t.Errorf("judgement lines = %d, want 3", n)
	}
	if strings.Index(out, "1. 고치는 법") > strings.Index(out, "**해당 결과 3건**") {
		t.Errorf("the list is above the shared text:\n%s", out)
	}
	// The finding with other text keeps the layout of a single finding.
	if !strings.Contains(out, "### [보통] 키 파일\n\n- 번호: DV-204\n- 위치: `~/a/id.json`\n- 판단: 확실\n\n다른 설명\n") {
		t.Errorf("single finding changed:\n%s", out)
	}
}

// Only text that is the same is said once: the same number with another
// title, explanation, fix or severity stays a section of its own.
func TestMarkdownKeepsDifferingTextApart(t *testing.T) {
	a := sameTextFinding("a", "", "")
	for name, change := range map[string]func(*finding.Finding){
		"title":    func(f *finding.Finding) { f.Title = "다른 제목" },
		"explain":  func(f *finding.Finding) { f.ExplainKo = "다른 설명" },
		"fix":      func(f *finding.Finding) { f.Fix = "다른 수정" },
		"severity": func(f *finding.Finding) { f.Severity = finding.High },
		"refs":     func(f *finding.Finding) { f.References = []string{"https://example.test/other"} },
		"mappings": func(f *finding.Finding) { f.Mappings = nil },
		"id":       func(f *finding.Finding) { f.ID = "DV-203" },
	} {
		b := sameTextFinding("b", "", "")
		change(&b)
		out := markdownOf(t, Report{Findings: []finding.Finding{a, b}})
		if n := strings.Count(out, "\n- 번호: "); n != 2 || strings.Contains(out, "해당 결과") {
			t.Errorf("%s: %d sections:\n%s", name, n, out)
		}
	}
}

// What differs between findings of one section is said for each: the line,
// "under attack now", the .adkignore hint.
func TestMarkdownListKeepsPerFindingFacts(t *testing.T) {
	a, b := sameTextFinding("app/a.py", "aaaaaaaaaaaaaaaa", "x = `1`"), sameTextFinding("app/b.py", "bbbbbbbbbbbbbbbb", "")
	a.Line, b.Exploited, b.Confidence = 7, true, finding.Suspect
	out := markdownOf(t, Report{Findings: []finding.Finding{a, b}})
	for _, want := range []string{
		"위치: `app/a.py:7`", "   - 지문: aaaaaaaaaaaaaaaa (무시하려면 .adkignore에 추가)", "   - 근거: `x = '1'`",
		"   - 판단: 의심", "   - 실제 공격 중: 예 (CISA KEV 목록에 있음)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "실제 공격 중"); n != 1 {
		t.Errorf("'under attack' lines = %d, want 1", n)
	}
}

// The notes of a check that completed are in the Markdown report.
func TestMarkdownShowsNotes(t *testing.T) {
	out := markdownOf(t, Report{Kind: KindDevice, Checks: []checker.CheckStatus{
		{Name: "device", Status: checker.StatusOK, Notes: []string{"시드 문구를 찾아본 폴더: ~/Documents. 읽은 글 파일 725개.", "읽지 않은 것: 1MiB보다 큰 글 파일 13개"}},
	}})
	for _, want := range []string{"> 참고\n>\n", "> - device: 시드 문구를 찾아본 폴더: ~/Documents. 읽은 글 파일 725개.", "> - device: 읽지 않은 것: 1MiB보다 큰 글 파일 13개"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "일부 점검을 하지 못했습니다") {
		t.Errorf("notes are shown as a warning:\n%s", out)
	}
}
