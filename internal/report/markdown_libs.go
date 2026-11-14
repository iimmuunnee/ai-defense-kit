package report

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 라이브러리 취약점은 공지(GHSA 등) 하나가 결과 한 건이라, 같은 라이브러리
// 한 버전이 수십 건으로 나온다. Markdown에서는 잠금 파일과 라이브러리@버전마다
// 한 절로 묶는다. 공지마다의 번호, 등급, 수정 방법, 지문은 그 안에 남는다.
// JSON과 SARIF는 바꾸지 않는다.

const docsLockfileHeading = "## 문서·예제 폴더의 잠금 파일 (앱 본체가 아닐 수 있음)"

func isLib(f finding.Finding) bool { return f.Source == "deps" && f.Package != "" }

func libKey(f finding.Finding) string { return f.Location + "\x00" + f.Package }

// isDocsLib is a library finding from a documentation, example or test
// folder's lockfile: deps marks those Suspect.
func isDocsLib(f finding.Finding) bool { return isLib(f) && f.Confidence == finding.Suspect }

// libGroups returns the library findings of fs grouped by lockfile and
// version, in the order of each group's first finding.
func libGroups(fs []finding.Finding) (order []string, groups map[string][]finding.Finding) {
	groups = map[string][]finding.Finding{}
	for _, f := range fs {
		if !isLib(f) {
			continue
		}
		k := libKey(f)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}
	return order, groups
}

func libTitle(g []finding.Finding) string {
	return fmt.Sprintf("%s: 취약점 공지 %d건", g[0].Package, len(g))
}

// writeLibSummary says how many versions the library findings are.
func writeLibSummary(b *strings.Builder, fs []finding.Finding) {
	order, groups := libGroups(fs)
	if len(order) == 0 {
		return
	}
	n, docs := 0, 0
	for _, k := range order {
		n += len(groups[k])
		if isDocsLib(groups[k][0]) {
			docs++
		}
	}
	fmt.Fprintf(b, "라이브러리 취약점 결과 %d건은 라이브러리·버전 %d개입니다.", n, len(order))
	if docs > 0 {
		fmt.Fprintf(b, " 그중 %d개는 문서·예제 폴더의 잠금 파일입니다.", docs)
	}
	b.WriteString("\n\n")
}

// writeLibSection prints one library version and its advisories.
func writeLibSection(b *strings.Builder, g []finding.Finding, noIgnoreAdvice bool) {
	f := g[0] // fs is sorted, so the first is the most severe
	fmt.Fprintf(b, "### [%s] %s\n\n", severityKo[f.Severity], markdownText(libTitle(g)))
	fmt.Fprintf(b, "- 위치: `%s`\n", codeSpanLocation(f))
	fmt.Fprintf(b, "- 판단: %s\n", confidenceKo(f.Confidence))
	kev := 0
	for _, x := range g {
		if x.Exploited {
			kev++
		}
	}
	if kev > 0 {
		fmt.Fprintf(b, "- 실제 공격 중: 공지 %d건이 CISA KEV 목록에 있음\n", kev)
	}
	if v := highestFix(g); v != "" && len(g) > 1 {
		fmt.Fprintf(b, "- 모두 고치려면 %s 이상으로 올리세요 (공지마다 고친 버전 중 가장 높은 것)\n", v)
	}
	if f.ExplainKo != "" {
		fmt.Fprintf(b, "\n%s\n", strings.TrimSpace(f.ExplainKo))
	}
	writeMappings(b, f.Mappings)
	fmt.Fprintf(b, "\n**공지 %d건**\n\n", len(g))
	prefix := f.Package + ": "
	for i, x := range g {
		fmt.Fprintf(b, "%d. [%s] %s - %s\n", i+1, severityKo[x.Severity], x.ID, markdownText(strings.TrimPrefix(x.Title, prefix)))
		if x.Fix != "" {
			fmt.Fprintf(b, "   - 수정 방법: %s\n", oneLine(markdownText(x.Fix)))
		}
		if x.Exploited {
			b.WriteString("   - 실제 공격 중: 예 (CISA KEV 목록에 있음)\n")
		}
		if x.Evidence != "" {
			fmt.Fprintf(b, "   - 근거: `%s`\n", oneLine(codeSpan(x.Evidence)))
		}
		if x.Fingerprint != "" && noIgnoreAdvice {
			fmt.Fprintf(b, "   - 지문: %s\n", x.Fingerprint)
		} else if x.Fingerprint != "" {
			fmt.Fprintf(b, "   - 지문: %s (무시하려면 .adkignore에 추가)\n", x.Fingerprint)
		}
		if len(x.References) > 0 {
			fmt.Fprintf(b, "   - 참고 링크: %s\n", strings.Join(x.References, ", "))
		}
		if i > 0 && fmt.Sprint(x.Mappings) != fmt.Sprint(f.Mappings) {
			writeMappings(b, x.Mappings)
		}
	}
	b.WriteString("\n")
}

// writeDocsLibs prints the library versions of documentation, example and
// test lockfiles in their own part, after the main details.
func writeDocsLibs(b *strings.Builder, fs []finding.Finding, noIgnoreAdvice bool) {
	order, groups := libGroups(fs)
	var docs []string
	for _, k := range order {
		if isDocsLib(groups[k][0]) {
			docs = append(docs, k)
		}
	}
	if len(docs) == 0 {
		return
	}
	b.WriteString(docsLockfileHeading + "\n\n")
	b.WriteString("문서 사이트, 예제, 시험 자료 폴더(`docs`, `examples`, `testdata` 등)의 잠금 파일입니다. 서비스에 함께 배포되지 않는 경우가 많지만, 배포된다면 위의 결과와 똑같이 고쳐야 합니다. 등급은 낮추지 않았습니다.\n\n")
	for _, k := range docs {
		writeLibSection(b, groups[k], noIgnoreAdvice)
	}
}

// highestFix returns the highest version among the advisories' fixes when
// every fix reads "<version> 이상으로 올리세요", else "".
func highestFix(g []finding.Finding) string {
	const suffix = " 이상으로 올리세요"
	best := ""
	var bestV []int
	for _, f := range g {
		v, ok := strings.CutSuffix(strings.TrimSuffix(strings.TrimSpace(f.Fix), "."), suffix)
		if !ok || strings.ContainsAny(v, " ,") {
			return ""
		}
		nums, ok := versionNumbers(v)
		if !ok {
			return ""
		}
		c := compareVersions(nums, bestV)
		// 2.0.0 is above 2.0.0-rc.1 though their numbers are the same.
		if best == "" || c > 0 || c == 0 && strings.ContainsAny(best, "-+") && !strings.ContainsAny(v, "-+") {
			best, bestV = v, nums
		}
	}
	return best
}

// versionNumbers reads the leading dotted numbers of v ("1.2.3", "v1.2",
// "2.0.0-rc.1" counts as 2.0.0). It fails when v does not start with one.
func versionNumbers(v string) ([]int, bool) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func compareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}
