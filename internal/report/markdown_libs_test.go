package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func libFinding(id, loc, pkg string, sev finding.Severity, conf finding.Confidence, fix string) finding.Finding {
	return finding.Finding{ID: id, Source: "deps", Kind: "vuln-lib", Severity: sev, Confidence: conf,
		Location: loc, Package: pkg, Evidence: pkg + " (메모)", Title: pkg + ": " + id + " 제목",
		ExplainKo: "취약한 라이브러리 설명", Fix: fix, References: []string{"https://osv.dev/vulnerability/" + id},
		Fingerprint: "fp-" + id}
}

func libReport(fs ...finding.Finding) string {
	r := Report{Target: ".", ScannedAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), ToolVersion: "t", Findings: fs}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		panic(err)
	}
	return buf.String()
}

// 같은 잠금 파일의 같은 라이브러리@버전은 공지가 여러 개여도 한 절로 묶는다.
// 공지마다의 번호, 등급, 수정 방법, 지문은 그 안에 그대로 남는다.
func TestMarkdownGroupsAdvisoriesOfOneLibraryVersion(t *testing.T) {
	md := libReport(
		libFinding("GHSA-a", "package-lock.json", "next@14.0.4", finding.High, finding.Certain, "14.0.5 이상으로 올리세요"),
		libFinding("GHSA-b", "package-lock.json", "next@14.0.4", finding.Critical, finding.Certain, "14.2.25 이상으로 올리세요"),
		libFinding("GHSA-c", "package-lock.json", "next@14.0.4", finding.Medium, finding.Certain, "14.1.1 이상으로 올리세요"),
		libFinding("GHSA-d", "package-lock.json", "lodash@4.17.15", finding.High, finding.Certain, "4.17.21 이상으로 올리세요"),
	)
	if n := strings.Count(md, "### [치명] next@14.0.4: 취약점 공지 3건"); n != 1 {
		t.Errorf("next heading count %d:\n%s", n, md)
	}
	if !strings.Contains(md, "모두 고치려면 14.2.25 이상으로 올리세요") {
		t.Errorf("highest fix missing:\n%s", md)
	}
	for _, want := range []string{"GHSA-a", "GHSA-b", "GHSA-c", "fp-GHSA-a", "fp-GHSA-c", "14.0.5 이상으로 올리세요"} {
		if !strings.Contains(md, want) {
			t.Errorf("%q missing:\n%s", want, md)
		}
	}
	// 한 건뿐인 라이브러리도 같은 모양의 절로 나온다.
	if !strings.Contains(md, "### [높음] lodash@4.17.15: 취약점 공지 1건") {
		t.Errorf("lodash section missing:\n%s", md)
	}
	// "지금 당장 고칠 것"에는 라이브러리@버전마다 한 줄.
	top := md[strings.Index(md, "## 지금 당장 고칠 것"):strings.Index(md, "## 요약")]
	if strings.Count(top, "next@14.0.4") != 1 {
		t.Errorf("top list repeats next:\n%s", top)
	}
	if !strings.Contains(md, "라이브러리 취약점 결과 4건은 라이브러리·버전 2개입니다.") {
		t.Errorf("summary line missing:\n%s", md)
	}
}

// 문서·예제 폴더 잠금 파일("의심")의 라이브러리는 따로 모아 보여 주고, 지금 당장 고칠 것에는 넣지 않는다.
func TestMarkdownSeparatesDocsLockfiles(t *testing.T) {
	md := libReport(
		libFinding("GHSA-a", "package-lock.json", "next@14.0.4", finding.High, finding.Certain, "14.0.5 이상으로 올리세요"),
		libFinding("GHSA-x", "dev-docs/yarn.lock", "next@13.0.0", finding.Critical, finding.Suspect, "14.0.5 이상으로 올리세요"),
	)
	i := strings.Index(md, "## 문서·예제 폴더의 잠금 파일")
	if i < 0 {
		t.Fatalf("docs section missing:\n%s", md)
	}
	if !strings.Contains(md[i:], "next@13.0.0") || strings.Contains(md[:i], "### [치명] next@13.0.0") {
		t.Errorf("docs lockfile library not only in its section:\n%s", md)
	}
	top := md[strings.Index(md, "## 지금 당장 고칠 것"):strings.Index(md, "## 요약")]
	if strings.Contains(top, "next@13.0.0") {
		t.Errorf("docs lockfile in top list:\n%s", top)
	}
	if !strings.Contains(md, "라이브러리 취약점 결과 2건은 라이브러리·버전 2개입니다. 그중 1개는 문서·예제 폴더의 잠금 파일입니다.") {
		t.Errorf("summary line missing:\n%s", md)
	}
}

func TestHighestFix(t *testing.T) {
	g := func(fixes ...string) []finding.Finding {
		var out []finding.Finding
		for _, f := range fixes {
			out = append(out, finding.Finding{Fix: f})
		}
		return out
	}
	for _, c := range []struct {
		fixes []string
		want  string
	}{
		{[]string{"1.2.3 이상으로 올리세요", "1.10.0 이상으로 올리세요", "1.9.9 이상으로 올리세요"}, "1.10.0"},
		{[]string{"2.0.0-rc.1 이상으로 올리세요", "2.0.0 이상으로 올리세요"}, "2.0.0"},
		{[]string{"2.0.0 이상으로 올리세요", "2.0.0-rc.1 이상으로 올리세요"}, "2.0.0"},
		{[]string{"1.2.3 이상으로 올리세요", "고친 버전이 아직 없습니다"}, ""},
		{[]string{"1.2.3 이상으로 올리세요", "1.2.3 또는 2.0.1 이상으로 올리세요"}, ""},
	} {
		if got := highestFix(g(c.fixes...)); got != c.want {
			t.Errorf("%v: got %q, want %q", c.fixes, got, c.want)
		}
	}
}

// 문서·예제 잠금 파일 결과만 있으면 빈 "상세" 절을 만들지 않는다.
func TestMarkdownOnlyDocsLibsHasNoEmptyDetails(t *testing.T) {
	md := libReport(libFinding("GHSA-x", "docs/yarn.lock", "next@13.0.0", finding.High, finding.Suspect, "14.0.5 이상으로 올리세요"))
	if strings.Contains(md, "## 상세") || !strings.Contains(md, docsLockfileHeading) {
		t.Errorf("unexpected layout:\n%s", md)
	}
}
