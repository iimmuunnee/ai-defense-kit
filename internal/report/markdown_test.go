package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

var update = flag.Bool("update", false, "rewrite testdata/report/golden*.md")

func fixedReport() Report {
	return Report{
		Target:      "./my-app",
		Stacks:      []string{"fastapi", "nextjs"},
		ScannedAt:   time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC),
		ToolVersion: "v0.1.0",
		GitCommit:   "0123456789abcdef0123456789abcdef01234567",
		Findings: []finding.Finding{
			{ID: "DEP-CVE-2021-44228", Source: "deps", Severity: finding.Medium, Confidence: finding.Certain,
				Location: "package-lock.json", Fingerprint: "1111aaaa2222bbbb", Title: "취약한 라이브러리: lodash 4.17.15",
				ExplainKo: "알려진 취약점이 있는 버전입니다.", Fix: "4.17.21 이상으로 올리세요.",
				References: []string{"https://osv.dev/GHSA-xxxx"}},
			{ID: "SECRET-generic-api-key", Source: "secrets", Severity: finding.High, Confidence: finding.Certain,
				Location: "config.py", Line: 3, Fingerprint: "3333cccc4444dddd", Evidence: `api_key = "K7Q2****"`, Title: "코드에 키가 들어 있습니다",
				ExplainKo: "키가 저장소에 있으면 누구나 쓸 수 있습니다.", Fix: "키를 폐기하고 환경 변수로 옮기세요."},
			{ID: "KR-PAY-002", Source: "rules", Severity: finding.High, Confidence: finding.Suspect,
				Location: "app/webhook.py", Line: 8, Fingerprint: "5555eeee6666ffff", Title: "포트원 웹훅 검증 누락",
				ExplainKo: "서명을 확인하지 않으면 가짜 결제 알림을 받을 수 있습니다.", Fix: "Webhook.verify를 호출하세요.",
				References: []string{"https://jsr.io/@portone/server-sdk/doc/~/Webhook"},
				Mappings:   []finding.Mapping{{ID: "ISMSP-2.10.4", ReviewStatus: "draft"}}},
			{ID: "INFO-1", Source: "rules", Severity: finding.Info, Confidence: finding.Suspect,
				Location: "README.md", Title: "참고 사항"},
		},
		Checks: []checker.CheckStatus{
			{Name: "rules", Status: checker.StatusOK},
			{Name: "secrets", Status: checker.StatusOK, Warnings: []string{"git 기록이 없어 과거 커밋은 확인하지 못함"}},
			{Name: "deps", Status: checker.StatusFailed, Error: "OSV 조회 실패: network unreachable"},
		},
	}
}

func TestMarkdownGolden(t *testing.T) {
	checkGolden(t, fixedReport(), "../../testdata/report/golden.md")
}

func checkGolden(t *testing.T, r Report, path string) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(want) {
		t.Errorf("markdown differs from golden (run with -update):\n%s", buf.String())
	}
}

// A backtick in a path would end the code span around it and make the rest
// active Markdown. Only the Markdown changes; the finding keeps the exact path.
func TestMarkdownLocationKeepsItsCodeSpan(t *testing.T) {
	loc := "a`[click here](https:/evil.example/x)`b/.mcp.json"
	r := Report{Findings: []finding.Finding{{ID: "AR-004", Severity: finding.Medium, Title: "t", Location: loc, Line: 3}}}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	const want = "`a'[click here](https:/evil.example/x)'b/.mcp.json:3`"
	if got := strings.Count(buf.String(), want); got != 2 {
		t.Errorf("code spans = %d, want 2 in\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), loc) {
		t.Error("raw path in the report")
	}
	if r.Findings[0].Location != loc {
		t.Errorf("location changed: %q", r.Findings[0].Location)
	}
}

func TestMarkdownShowsFailedChecks(t *testing.T) {
	r := Report{Target: "x", ScannedAt: time.Now(), Checks: []checker.CheckStatus{
		{Name: "deps", Status: checker.StatusFailed, Error: "boom"},
	}}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "일부 점검을 하지 못했습니다") || !strings.Contains(out, "deps") {
		t.Errorf("failed check not shown:\n%s", out)
	}
	if strings.Contains(out, "찾은 문제가 없습니다") {
		t.Errorf("must not claim no problems:\n%s", out)
	}
}

func TestMarkdownNoFindings(t *testing.T) {
	r := Report{Target: "x", ScannedAt: time.Now(), Checks: []checker.CheckStatus{{Name: "rules", Status: checker.StatusOK}}}
	var buf bytes.Buffer
	_ = WriteMarkdown(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "찾은 문제가 없습니다.") || !strings.HasSuffix(out, Disclaimer+"\n") {
		t.Errorf("unexpected:\n%s", out)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, fixedReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"\n  \"target\": \"./my-app\"", `"stacks": [`, `"scanned_at": "`, `"tool_version": "`, `"git_commit": "`,
		`"findings": [`, `"checks": [`, `"ignored": `, `"severity": "high"`,
		`"name": "`, `"status": "`, `"error": "`, `"warnings": [`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("json lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\"Target\"") || strings.Contains(out, "\"Status\"") {
		t.Errorf("json has Go field names:\n%s", out)
	}
}

func TestWriteJSONNilSlicesAreEmptyArrays(t *testing.T) {
	r := Report{
		Target:   "x",
		Findings: []finding.Finding{{ID: "a", Severity: finding.Low}},
		Checks:   []checker.CheckStatus{{Name: "rules", Status: checker.StatusOK}},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "null") {
		t.Errorf("json has null:\n%s", buf.String())
	}
	buf.Reset()
	if err := WriteJSON(&buf, Report{Target: "x"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"stacks": []`, `"findings": []`, `"checks": []`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("json lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestMarkdownShowsIgnoredCount(t *testing.T) {
	r := Report{Target: "x", ScannedAt: time.Now(), Ignored: 2}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "무시함: 2개") || strings.Contains(buf.String(), "찾은 문제가 없습니다") {
		t.Errorf("got:\n%s", buf.String())
	}
}

func assetFinding(id, name, ev string) finding.Finding {
	title := "인증서 공개 기록에서 찾은 서브도메인: " + name
	if id == "AS-001" {
		title = "목록에 없는 서브도메인: " + name
	}
	return finding.Finding{ID: id, Source: "assets", Severity: finding.Info, Confidence: finding.Suspect,
		Location: name, Evidence: ev, Title: title, ExplainKo: "확인해 볼 목록입니다.\n",
		Fingerprint: finding.MakeFingerprint(id, name, name)}
}

func fixedAssetsReport() Report {
	d := func(y, m, day int) time.Time { return time.Date(y, time.Month(m), day, 0, 0, 0, 0, time.UTC) }
	api := assetFinding("AS-002", "api.example.test", "인증서 1개, 처음 발급 2026-11-20, 마지막 만료 2027-02-18, 지금 유효한 인증서 없음 (소유 미확인)")
	dev := assetFinding("AS-002", "dev.example.test", "인증서 3개, 처음 발급 2025-01-01, 마지막 만료 2027-05-02, 지금 유효함 (소유 미확인)")
	for _, f := range []*finding.Finding{&api, &dev} {
		f.Mappings = []finding.Mapping{{ID: "ISMSP-2.6.1", Name: "접근통제 2.6.1", Clause: "2.6.1", ReviewStatus: "checked", CheckedBy: "Claude (AI)", CheckedAt: "2026-11-05"}}
	}
	return Report{
		Kind:        KindAssets,
		Target:      "example.test",
		ScannedAt:   time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC),
		ToolVersion: "v0.4.0",
		// 순서가 섞여 있어도 이름 순으로 써야 한다.
		Findings: []finding.Finding{dev, api},
		Assets: []AssetRow{
			{Name: "api.example.test", CertCount: 1, FirstSeen: d(2026, 11, 20), LastExpiry: d(2027, 2, 18), Fingerprint: api.Fingerprint},
			{Name: "dev.example.test", Wildcard: true, CertCount: 3, FirstSeen: d(2025, 1, 1), LastExpiry: d(2027, 5, 2), StillValid: true, Fingerprint: dev.Fingerprint},
		},
		Ignored: 1,
		Checks: []checker.CheckStatus{
			{Name: "assets", Status: checker.StatusOK, Warnings: []string{"crt.sh 결과가 10000행 한도에 닿아 일부만 받았을 수 있습니다. --exclude-expired로 다시 확인해 보세요."}},
		},
	}
}

func TestMarkdownAssetsGolden(t *testing.T) {
	checkGolden(t, fixedAssetsReport(), "../../testdata/report/golden-assets.md")
}

func TestMarkdownAssetsNoFindings(t *testing.T) {
	r := Report{Kind: KindAssets, Target: "example.test", ScannedAt: time.Now(),
		Checks: []checker.CheckStatus{{Name: "assets", Status: checker.StatusOK}}}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# adk 자산 리포트\n",
		"인증서 투명성(CT) 공개 기록만 조회했고, 찾은 주소에는 접속하지 않았습니다. 모든 결과는 소유를 확인하지 않은 정보입니다.",
		"인증서 공개 기록에서 찾은 서브도메인이 없습니다.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"찾은 문제가 없습니다", "지금 당장 고칠 것", "## 확인해 볼 서브도메인", "스택:"} {
		if strings.Contains(out, bad) {
			t.Errorf("must not contain %q:\n%s", bad, out)
		}
	}
	if !strings.HasSuffix(out, Disclaimer+"\n") {
		t.Errorf("no disclaimer:\n%s", out)
	}

	// 알려진 목록을 썼으면 "없음"이 아니라 "목록에 없는 이름이 없음"이다.
	r.KnownList = "known.txt"
	buf.Reset()
	_ = WriteMarkdown(&buf, r)
	if !strings.Contains(buf.String(), "알려진 목록에 없는 서브도메인이 없습니다.") || !strings.Contains(buf.String(), "- 알려진 목록: known.txt") {
		t.Errorf("known:\n%s", buf.String())
	}
}

func TestMarkdownAssetsFailed(t *testing.T) {
	r := Report{Kind: KindAssets, Target: "example.test", ScannedAt: time.Now(),
		Checks: []checker.CheckStatus{{Name: "assets", Status: checker.StatusFailed, Error: "crt.sh 조회에 실패했습니다: HTTP 502"}}}
	var buf bytes.Buffer
	_ = WriteMarkdown(&buf, r)
	if strings.Contains(buf.String(), "서브도메인이 없습니다") || !strings.Contains(buf.String(), "assets (실패)") {
		t.Errorf("failed lookup must not look empty:\n%s", buf.String())
	}
}

func TestWriteJSONKind(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Report{Target: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"kind": "code"`) || strings.Contains(buf.String(), `"assets"`) {
		t.Errorf("code json:\n%s", buf.String())
	}
	buf.Reset()
	if err := WriteJSON(&buf, Report{Kind: KindAssets, Target: "example.test"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"kind": "assets"`) || !strings.Contains(buf.String(), `"assets": []`) {
		t.Errorf("assets json:\n%s", buf.String())
	}
	buf.Reset()
	if err := WriteJSON(&buf, fixedAssetsReport()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "dev.example.test"`, `"wildcard": true`, `"cert_count": 3`, `"last_expiry": "2027-05-02T00:00:00Z"`, `"still_valid": true`, `"fingerprint": "`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestMarkdownMappingStatus(t *testing.T) {
	const name = "정보보호 및 개인정보보호 관리체계 인증기준 2.10.4"
	tests := []struct {
		label string
		m     finding.Mapping
		want  string
	}{
		{"checked", finding.Mapping{ID: "ISMSP-2.10.4", Name: name, Clause: "2.10.4", ReviewStatus: "checked", CheckedBy: "Claude (AI)", CheckedAt: "2026-11-05"},
			"- " + name + " (2.10.4): 원문 대조함: Claude (AI), 2026-11-05 · 전문가 검수 전\n"},
		{"checked, no clause", finding.Mapping{ID: "X", Name: name, ReviewStatus: "checked", CheckedBy: "Claude (AI)", CheckedAt: "2026-11-05"},
			"- " + name + ": 원문 대조함: Claude (AI), 2026-11-05 · 전문가 검수 전\n"},
		{"expert", finding.Mapping{ID: "X", Name: name, Clause: "2.10.4", ReviewStatus: "expert", CheckedBy: "홍길동", CheckedAt: "2026-12-01"},
			"- " + name + " (2.10.4): 전문가 검수함: 홍길동, 2026-12-01\n"},
		{"draft", finding.Mapping{ID: "X", Name: name, ReviewStatus: "draft"},
			"- " + name + ": 검수 전 (원문 대조 안 함)\n"},
		{"empty status", finding.Mapping{ID: "X", Name: name},
			"- " + name + ": 검수 전 (원문 대조 안 함)\n"},
		{"no name", finding.Mapping{ID: "ISMSP-9.9.9", ReviewStatus: "draft"},
			"- ISMSP-9.9.9: 기준 정보 없음 (검수 전)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			var b strings.Builder
			writeMappings(&b, []finding.Mapping{tt.m})
			want := "\n**국내 기준**\n\n" + tt.want
			if b.String() != want {
				t.Errorf("got %q, want %q", b.String(), want)
			}
		})
	}
	var b strings.Builder
	writeMappings(&b, nil)
	if b.Len() != 0 {
		t.Errorf("empty list wrote %q", b.String())
	}
}

func TestAssetsMarkdownMappings(t *testing.T) {
	r := fixedAssetsReport()
	for i := range r.Findings {
		r.Findings[i].Mappings = []finding.Mapping{{ID: "ISMSP-2.6.1", Name: "접근통제 2.6.1", ReviewStatus: "draft"}}
	}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if n := strings.Count(out, "**국내 기준**"); n != 1 {
		t.Fatalf("heading count = %d, want 1:\n%s", n, out)
	}
	want := "확인해 볼 목록입니다.\n\n**국내 기준**\n\n- 접근통제 2.6.1: 검수 전 (원문 대조 안 함)\n"
	if !strings.Contains(out, want) {
		t.Errorf("mapping not right after explanation:\n%s", out)
	}
}

func TestJSONMappingFields(t *testing.T) {
	r := fixedReport()
	r.Findings[2].Mappings = []finding.Mapping{{ID: "ISMSP-2.10.4", Name: "n", Clause: "2.10.4", ReviewStatus: "checked",
		CheckedBy: "Claude (AI)", CheckedAt: "2026-11-05", SourceURL: "https://example.test/x"}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			Mappings []map[string]any `json:"mappings"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	m := got.Findings[2].Mappings[0]
	for _, k := range []string{"id", "name", "clause", "review_status", "checked_by", "checked_at", "source_url"} {
		if _, ok := m[k]; !ok {
			t.Errorf("mappings[0] lacks %q: %v", k, m)
		}
	}
}

// A device report is about a computer, not a source folder: it has no stack
// list and no git commit, so JSON leaves both out. Code reports keep them.
func TestDeviceJSONLeavesOutFolderFields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Report{Kind: KindDevice, Target: "x"}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"stacks"`, `"git_commit"`} {
		if strings.Contains(buf.String(), field) {
			t.Errorf("device json has %s:\n%s", field, buf.String())
		}
	}
	for _, want := range []string{`"kind": "device"`, `"findings": []`, `"checks": []`, `"scanned_at"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("device json lacks %s:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := WriteJSON(&buf, Report{Target: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"stacks": []`) || !strings.Contains(buf.String(), `"git_commit": ""`) {
		t.Errorf("code json changed:\n%s", buf.String())
	}
}
