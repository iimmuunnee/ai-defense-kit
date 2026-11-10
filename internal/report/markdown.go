package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const topCount = 3

var severityKo = map[finding.Severity]string{
	finding.Critical: "치명",
	finding.High:     "높음",
	finding.Medium:   "보통",
	finding.Low:      "낮음",
	finding.Info:     "참고",
}

func confidenceKo(c finding.Confidence) string {
	if c == finding.Certain {
		return "확실"
	}
	return "의심"
}

func statusKo(s checker.Status) string {
	switch s {
	case checker.StatusFailed:
		return "실패"
	case checker.StatusSkipped:
		return "건너뜀"
	}
	return "완료"
}

func locationOf(f finding.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Location, f.Line)
	}
	return f.Location
}

// codeSpanLocation is the location as shown inside a code span.
func codeSpanLocation(f finding.Finding) string {
	return codeSpan(locationOf(f))
}

// WriteMarkdown writes r as a Korean Markdown report.
func WriteMarkdown(w io.Writer, r Report) error {
	if r.isAssets() {
		return writeAssetsMarkdown(w, r)
	}
	var b strings.Builder
	b.WriteString("# adk 점검 리포트\n\n")
	if r.Ignored > 0 && !r.Untrusted {
		fmt.Fprintf(&b, "> ⚠️ %s\n\n", HidingWarning(r.Ignored))
	}
	fmt.Fprintf(&b, "- 대상: %s\n", r.Target)
	// A device report is about this computer: it has no stack or commit.
	device := r.Kind == KindDevice
	if !device {
		stacks := "없음"
		if len(r.Stacks) > 0 {
			stacks = strings.Join(r.Stacks, ", ")
		}
		fmt.Fprintf(&b, "- 스택: %s\n", stacks)
	}
	fmt.Fprintf(&b, "- 점검 시각: %s\n", r.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- 도구 버전: %s\n", r.ToolVersion)
	if !device {
		commit := r.GitCommit
		if commit == "" {
			commit = "알 수 없음"
		}
		fmt.Fprintf(&b, "- git 커밋: %s\n", commit)
	}
	if r.Untrusted {
		b.WriteString("- 받은 저장소 모드: --untrusted\n")
	}
	b.WriteString("\n")

	failed := writeChecks(&b, r.Checks)
	writeNotes(&b, r.Checks)

	fs := append([]finding.Finding(nil), r.Findings...)
	finding.Sort(fs)

	if len(fs) == 0 && r.Ignored == 0 && !failed {
		b.WriteString("찾은 문제가 없습니다.\n\n")
	}
	if len(fs) > 0 || r.Ignored > 0 {
		writeTop(&b, fs)
		writeSummary(&b, fs, r.Ignored)
		writeDetails(&b, fs, r.NoIgnoreAdvice)
	}

	b.WriteString("---\n\n")
	b.WriteString(Disclaimer + "\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// writeChecks prints the warning block and reports whether any check failed
// or was skipped.
func writeChecks(b *strings.Builder, checks []checker.CheckStatus) bool {
	var lines []string
	bad := false
	for _, c := range checks {
		if c.Status != checker.StatusOK {
			bad = true
			lines = append(lines, fmt.Sprintf("> - %s (%s): %s", c.Name, statusKo(c.Status), markdownText(c.Error)))
		}
		for _, w := range c.Warnings {
			lines = append(lines, fmt.Sprintf("> - %s: %s", c.Name, markdownText(w)))
		}
	}
	if len(lines) == 0 {
		return false
	}
	b.WriteString("> ⚠️ 일부 점검을 하지 못했습니다\n>\n")
	b.WriteString(strings.Join(lines, "\n"))
	b.WriteString("\n\n")
	return bad
}

// writeNotes prints remarks on checks that completed, apart from the warning
// block: nothing is missing from the results because of them.
func writeNotes(b *strings.Builder, checks []checker.CheckStatus) {
	var lines []string
	for _, c := range checks {
		for _, n := range c.Notes {
			lines = append(lines, fmt.Sprintf("> - %s: %s", c.Name, markdownText(n)))
		}
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("> 참고\n>\n")
	b.WriteString(strings.Join(lines, "\n"))
	b.WriteString("\n\n")
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func writeTop(b *strings.Builder, fs []finding.Finding) {
	var top []finding.Finding
	for _, f := range fs {
		if f.Severity != finding.Info && len(top) < topCount {
			top = append(top, f)
		}
	}
	if len(top) == 0 {
		return
	}
	b.WriteString("## 지금 당장 고칠 것\n\n")
	for i, f := range top {
		fmt.Fprintf(b, "%d. [%s] %s - `%s`\n", i+1, severityKo[f.Severity], markdownText(f.Title), codeSpanLocation(f))
	}
	b.WriteString("\n")
}

func writeSummary(b *strings.Builder, fs []finding.Finding, ignored int) {
	counts := map[finding.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	b.WriteString("## 요약\n\n| 등급 | 개수 |\n| --- | --- |\n")
	order := []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}
	for _, s := range order {
		fmt.Fprintf(b, "| %s | %d |\n", severityKo[s], counts[s])
	}
	b.WriteString("\n")
	if ignored > 0 {
		fmt.Fprintf(b, "무시함: %d개 (.adkignore)\n\n", ignored)
	}
}

func writeDetails(b *strings.Builder, fs []finding.Finding, noIgnoreAdvice bool) {
	b.WriteString("## 상세\n\n")
	for _, f := range fs {
		fmt.Fprintf(b, "### [%s] %s\n\n", severityKo[f.Severity], markdownText(f.Title))
		fmt.Fprintf(b, "- 번호: %s\n", f.ID)
		fmt.Fprintf(b, "- 위치: `%s`\n", codeSpanLocation(f))
		fmt.Fprintf(b, "- 판단: %s\n", confidenceKo(f.Confidence))
		if f.Fingerprint != "" && noIgnoreAdvice {
			fmt.Fprintf(b, "- 지문: %s\n", f.Fingerprint)
		} else if f.Fingerprint != "" {
			fmt.Fprintf(b, "- 지문: %s (무시하려면 .adkignore에 추가)\n", f.Fingerprint)
		}
		if f.Exploited {
			b.WriteString("- 실제 공격 중: 예 (CISA KEV 목록에 있음)\n")
		}
		if f.Evidence != "" {
			fmt.Fprintf(b, "- 근거: `%s`\n", oneLine(codeSpan(f.Evidence)))
		}
		if f.ExplainKo != "" {
			fmt.Fprintf(b, "\n%s\n", strings.TrimSpace(f.ExplainKo))
		}
		if f.Fix != "" {
			fmt.Fprintf(b, "\n**수정 방법**\n\n%s\n", strings.TrimSpace(f.Fix))
		}
		if len(f.References) > 0 {
			b.WriteString("\n**참고 링크**\n\n")
			for _, ref := range f.References {
				fmt.Fprintf(b, "- %s\n", ref)
			}
		}
		writeMappings(b, f.Mappings)
		b.WriteString("\n")
	}
}

// AssetsNotice says what an assets report did and did not do.
const AssetsNotice = "인증서 투명성(CT) 공개 기록만 조회했고, 찾은 주소에는 접속하지 않았습니다. 모든 결과는 소유를 확인하지 않은 정보입니다."

func writeAssetsMarkdown(w io.Writer, r Report) error {
	var b strings.Builder
	b.WriteString("# adk 자산 리포트\n\n")
	fmt.Fprintf(&b, "- 대상: %s\n", r.Target)
	if r.KnownList != "" {
		fmt.Fprintf(&b, "- 알려진 목록: %s\n", r.KnownList)
	}
	fmt.Fprintf(&b, "- 점검 시각: %s\n", r.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- 도구 버전: %s\n\n", r.ToolVersion)
	b.WriteString(AssetsNotice + "\n\n")

	failed := writeChecks(&b, r.Checks)

	fs := append([]finding.Finding(nil), r.Findings...)
	finding.Sort(fs) // all Info/Suspect, so this orders by name

	if len(fs) == 0 && r.Ignored == 0 && !failed {
		if r.KnownList != "" {
			b.WriteString("알려진 목록에 없는 서브도메인이 없습니다.\n\n")
		} else {
			b.WriteString("인증서 공개 기록에서 찾은 서브도메인이 없습니다.\n\n")
		}
	}
	if len(fs) > 0 || r.Ignored > 0 {
		writeAssetTable(&b, fs, r.Assets)
		if r.Ignored > 0 {
			fmt.Fprintf(&b, "무시함: %d개 (.adkignore)\n\n", r.Ignored)
		}
		writeAssetExplain(&b, fs)
	}

	b.WriteString("---\n\n")
	b.WriteString(Disclaimer + "\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func writeAssetTable(b *strings.Builder, fs []finding.Finding, rows []AssetRow) {
	byFP := map[string]AssetRow{}
	for _, a := range rows {
		byFP[a.Fingerprint] = a
	}
	fmt.Fprintf(b, "## 확인해 볼 서브도메인 (%d개)\n\n", len(fs))
	if len(fs) == 0 {
		return
	}
	b.WriteString("| 이름 | 인증서 수 | 마지막 만료 | 상태 | 지문 |\n| --- | --- | --- | --- | --- |\n")
	for _, f := range fs {
		name := "`" + f.Location + "`"
		count, expiry, state := "-", "-", "-"
		if a, ok := byFP[f.Fingerprint]; ok {
			if a.Wildcard {
				name += " (와일드카드 인증서)"
			}
			count = fmt.Sprint(a.CertCount)
			expiry = "알 수 없음"
			if !a.LastExpiry.IsZero() {
				expiry = a.LastExpiry.UTC().Format("2006-01-02")
			}
			state = "유효한 인증서 없음"
			if a.StillValid {
				state = "유효"
			}
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", name, count, expiry, state, f.Fingerprint)
	}
	b.WriteString("\n표의 이름은 모두 소유 미확인입니다. 지문을 .adkignore에 적으면 다음부터 이 표에서 빠집니다.\n\n")
}

// writeAssetExplain prints each explanation once: every finding of one ID
// shares the same text.
func writeAssetExplain(b *strings.Builder, fs []finding.Finding) {
	seen := map[string]bool{}
	type entry struct {
		text string
		ms   []finding.Mapping
	}
	var texts []entry
	for _, f := range fs {
		if seen[f.ID] || strings.TrimSpace(f.ExplainKo) == "" {
			continue
		}
		seen[f.ID] = true
		texts = append(texts, entry{strings.TrimSpace(f.ExplainKo), f.Mappings})
	}
	if len(texts) == 0 {
		return
	}
	b.WriteString("## 이 목록을 보는 법\n\n")
	for _, t := range texts {
		b.WriteString(t.text + "\n")
		writeMappings(b, t.ms)
		b.WriteString("\n")
	}
}

// writeMappings prints the Korean-standard list for one finding (or one ID).
// It writes nothing for an empty list.
func writeMappings(b *strings.Builder, ms []finding.Mapping) {
	if len(ms) == 0 {
		return
	}
	ms = append([]finding.Mapping(nil), ms...)
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].ID < ms[j].ID })
	b.WriteString("\n**국내 기준**\n\n")
	for _, m := range ms {
		name := oneLine(m.Name)
		if name == "" {
			fmt.Fprintf(b, "- %s: 기준 정보 없음 (검수 전)\n", oneLine(m.ID))
			continue
		}
		label := name
		if c := oneLine(m.Clause); c != "" {
			label += " (" + c + ")"
		}
		by, at := oneLine(m.CheckedBy), oneLine(m.CheckedAt)
		switch m.ReviewStatus {
		case "checked":
			fmt.Fprintf(b, "- %s: 원문 대조함: %s, %s · 전문가 검수 전\n", label, by, at)
		case "expert":
			fmt.Fprintf(b, "- %s: 전문가 검수함: %s, %s\n", label, by, at)
		default:
			fmt.Fprintf(b, "- %s: 검수 전 (원문 대조 안 함)\n", label)
		}
	}
}
