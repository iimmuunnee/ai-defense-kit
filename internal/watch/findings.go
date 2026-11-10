package watch

import (
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Source is the Finding.Source of everything this package reports.
const Source = "watch"

// Findings turns an Outcome into findings. Every Change becomes one finding:
// a field this package has no rule for is reported as WA-003 rather than
// dropped. A target whose RPC endpoints disagreed gets WA-004. Targets that
// are only unverified, new or removed are not findings (ExitCode covers them).
// data supplies explain/<ID>.md and fixes/<ID>/watch.md; it may be nil.
func Findings(o Outcome, cfg Config, data fs.FS) []finding.Finding {
	allowed := map[string]map[string]bool{}
	targets := map[string]Target{}
	for _, t := range cfg.Targets {
		allowed[t.Key] = allowedDelegates(t)
		targets[t.Key] = t
	}
	text := newTexts(data)
	var out []finding.Finding

	stale := map[string]bool{}
	for _, k := range o.Stale {
		stale[k] = true
	}

	changed := map[string]bool{}
	for _, c := range o.Changes {
		changed[c.Key+"\x00"+c.Field] = true
	}

	for _, c := range o.Changes {
		t := targets[c.Key]
		rules := rulesOf(t.Kind)
		if rules.foldedInto != nil && changed[c.Key+"\x00"+rules.foldedInto(c.Field)] {
			continue
		}
		id, sev, title, topic := classify(t.Kind, c, allowed[c.Key])
		oldText, newText := shown(c.Old), shown(c.New)
		if rules.shownValue != nil {
			oldText, newText = rules.shownValue(c.Field, c.Old), rules.shownValue(c.Field, c.New)
		}
		evidence := c.Field + ": " + oldText + " -> " + newText
		if rules.describe != nil {
			if dTitle, dTopic, extra, ok := rules.describe(c, o.Observed[c.Key], t); ok {
				title, topic = dTitle, dTopic
				if extra != "" {
					title += " — " + extra
					evidence += " | " + extra
				}
			}
		}
		conf := finding.Certain
		if stale[c.Key] {
			// Same ID, severity and exit code: a possible change is never hidden.
			// Only the claim gets weaker, because the node may be behind the baseline.
			conf = finding.Suspect
			title = rules.stale.title(topic)
			evidence += rules.stale.evidence()
		}
		out = append(out, finding.Finding{
			ID:          id,
			Kind:        id,
			Source:      Source,
			Severity:    sev,
			Confidence:  conf,
			Location:    c.Key,
			Evidence:    evidence,
			Title:       title,
			ExplainKo:   text.explain(id),
			Fix:         text.fix(id),
			Fingerprint: finding.MakeFingerprint(id, c.Key, c.Field+"\x00"+c.Old+"\x00"+c.New),
		})
	}
	for _, im := range o.Outside {
		const id = "WA-103"
		field := imageField + im.Name
		note := "레지스트리 " + im.Registries + "은(는) allowed_registries 허용 목록 밖입니다"
		title := "허용 목록 밖 레지스트리의 컨테이너 이미지가 목록에 있습니다"
		evidence := field + ": " + shown(o.Observed[im.Key][field]) + " | " + note
		conf := finding.Certain
		if stale[im.Key] {
			conf = finding.Suspect
			title = "내보내기 파일 오래됨 의심: 허용 목록 밖 레지스트리의 이미지로 읽힘 (" + staleExportNotice + ")"
			evidence += " | " + staleExportNotice + ". 실제 상태가 아닐 수 있으니 kubectl get pods -A -o json 으로 다시 내보낸 뒤 확인하세요"
		}
		out = append(out, finding.Finding{
			ID:          id,
			Kind:        id,
			Source:      Source,
			Severity:    finding.High,
			Confidence:  conf,
			Location:    im.Key,
			Evidence:    evidence,
			Title:       title,
			ExplainKo:   text.explain(id),
			Fix:         text.fix(id),
			Fingerprint: finding.MakeFingerprint(id, im.Key, "outside\x00"+im.Name+"\x00"+im.Registries),
		})
	}
	for _, k := range o.Disagreed {
		const id = "WA-004"
		out = append(out, finding.Finding{
			ID:          id,
			Kind:        id,
			Source:      Source,
			Severity:    finding.High,
			Confidence:  finding.Certain,
			Location:    k,
			Evidence:    "RPC 주소들의 응답이 서로 다릅니다 (두 번 물어 두 번 모두 달랐습니다)",
			Title:       "RPC 응답이 서로 달라 확인하지 못했습니다",
			ExplainKo:   text.explain(id),
			Fix:         text.fix(id),
			Fingerprint: finding.MakeFingerprint(id, k, "disagree"),
		})
	}
	return out
}

// staleNotice is said of every finding read from a node that looks stopped.
const staleNotice = "멈춘 것으로 보이는 노드에서 읽은 값입니다"

// staleExportNotice is said of every finding read from an exported file that
// is older than max_age.
const staleExportNotice = "오래된 내보내기 파일에서 읽은 값입니다"

func isImageField(f string) bool {
	return strings.HasPrefix(f, imageField) || strings.HasPrefix(f, registryField)
}

// describeImageChange words a change of a container image. extra says whether
// the registry the image comes from is on allowed_registries, when the target
// has such a list and the registry is known.
func describeImageChange(c Change, cur Observation, allowed map[string]bool) (title, topic, extra string) {
	topic = "기준값과 다른 컨테이너 이미지로 읽힘"
	name, isReg := strings.CutPrefix(c.Field, registryField)
	switch {
	case isReg:
		title = "컨테이너 이미지를 받아 온 레지스트리가 기준값과 다릅니다"
	case c.New == "":
		title = "기준값에 있던 컨테이너가 보이지 않습니다(사라짐)"
	case c.Old == "":
		title = "기준값에 없던 컨테이너 이미지가 목록에 나타났습니다"
	default:
		title = "컨테이너 이미지의 digest가 기준값과 다릅니다"
	}
	if len(allowed) == 0 || c.New == "" {
		return title, topic, ""
	}
	if !isReg {
		name, _ = strings.CutPrefix(c.Field, imageField)
	}
	regs := cur[registryField+name]
	if regs == "" {
		return title, topic, ""
	}
	if outside := registriesOutside(regs, allowed); len(outside) > 0 {
		return title, topic, "레지스트리 " + strings.Join(outside, ",") + "은(는) allowed_registries 허용 목록 밖입니다"
	}
	return title, topic, "레지스트리 " + regs + "은(는) allowed_registries 허용 목록 안입니다"
}

// classify returns the finding for one change of a target of the given kind.
// topic names the change without stating it as a fact, for the title of a
// finding read from a stale source. What a field means depends on the kind: a
// field the kind has no rule for is WA-003.
func classify(kind string, c Change, allowed map[string]bool) (id string, sev finding.Severity, title, topic string) {
	rules := rulesOf(kind)
	if slices.Contains(rules.identity, c.Field) {
		return "WA-007", finding.High, "기준값이 다른 대상을 설명하고 있습니다 (" + c.Field + ")", "기준값과 다른 대상 (" + c.Field + ")"
	}
	if rules.classify != nil {
		if v, ok := rules.classify(c, allowed); ok {
			return v.id, v.sev, v.title, v.topic
		}
	}
	return "WA-003", finding.High, "기준값과 다른 값이 있습니다 (" + c.Field + ")", "기준값과 다른 값 (" + c.Field + ")"
}

func shown(s string) string {
	if s == "" {
		return "(없음)"
	}
	return s
}

// shownFlags adds the hexadecimal form of a flag word: XRPL's documents list
// the flags that way, and a decimal number cannot be read bit by bit.
func shownFlags(s string) string {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return shown(s)
	}
	return fmt.Sprintf("%s (0x%08x)", s, n)
}

func normAddr(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "0x")
}

func allowedDelegates(t Target) map[string]bool {
	m := map[string]bool{}
	switch v := t.Options["allowed_delegates"].(type) {
	case []string:
		for _, s := range v {
			m[normAddr(s)] = true
		}
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				m[normAddr(s)] = true
			}
		}
	}
	return m
}

type texts struct {
	data fs.FS
	memo map[string]string
}

func newTexts(data fs.FS) *texts { return &texts{data: data, memo: map[string]string{}} }

func (t *texts) read(path string) string {
	if t.data == nil {
		return ""
	}
	if s, ok := t.memo[path]; ok {
		return s
	}
	b, err := fs.ReadFile(t.data, path)
	s := ""
	if err == nil {
		s = string(b)
	}
	t.memo[path] = s
	return s
}

func (t *texts) explain(id string) string { return t.read("explain/" + id + ".md") }
func (t *texts) fix(id string) string     { return t.read("fixes/" + id + "/watch.md") }
