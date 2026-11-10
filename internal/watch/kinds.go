package watch

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// kindRules is everything that differs from one target kind to the next. A new
// kind adds its observer to the CLI's list and one entry here; nothing outside
// this package needs to know its name.
type kindRules struct {
	validate func(map[string]any) error
	// identity are the fields that say what the baseline describes. A change in
	// one is WA-007, and accept checks the new value like init does.
	identity []string
	// checkInitial refuses an observation about to enter the baseline for the
	// first time, when it points to a wrong address, file or root.
	checkInitial func(Target, Observation) error
	// classify names the finding of a change of a field this kind reads. A field
	// it does not know is WA-003, never dropped.
	classify func(c Change, allowed map[string]bool) (verdict, bool)
	// describe, when it applies, rewords the finding with what else is known.
	describe func(c Change, obs Observation, t Target) (title, topic, extra string, ok bool)
	// shownValue, when set, words one value of a field in the evidence.
	shownValue func(field, value string) string
	// foldedInto names the field a change is reported under when both changed.
	foldedInto func(field string) string
	stale      staleWords
	// notes are remarks on how a target is read, from its config alone.
	notes func(Target) []string
	// reportNotes are remarks for a check report on what was just read.
	reportNotes func(t Target, obs Observation, changes []Change) []string
	// warnings are said by init and accept about what they take in.
	warnings func(Target, Observation) []string
	// secrets are values of the config that must not reach any output.
	secrets func(Target) []string
}

// verdict is what a change is reported as. topic names it without stating it as
// a fact, for the title of a finding read from a stale source.
type verdict struct {
	id    string
	sev   finding.Severity
	title string
	topic string
}

// staleWords say how a finding read from a stale source is worded.
type staleWords struct {
	prefix, notice, advice string
}

var (
	staleNode = staleWords{prefix: "노드 멈춤 의심: ", notice: staleNotice, advice: "실제 변경이 아닐 수 있으니 노드 상태를 먼저 확인하세요"}
	staleFile = staleWords{prefix: "내보내기 파일 오래됨 의심: ", notice: staleExportNotice, advice: "실제 변경이 아닐 수 있으니 kubectl get pods -A -o json 으로 다시 내보낸 뒤 확인하세요"}
)

func (s staleWords) title(topic string) string {
	return s.prefix + topic + " (" + s.notice + ")"
}

func (s staleWords) evidence() string {
	return " | " + s.notice + ". " + s.advice
}

var kinds = map[string]kindRules{
	kindEVM: {
		validate:     validateEVMOptions,
		identity:     []string{"address", "type"},
		checkInitial: checkInitialEVM,
		classify:     classifyEVM,
		stale:        staleNode,
		notes:        rpcNotes,
		reportNotes:  evmReportNotes,
		warnings:     evmWarnings,
		secrets:      rpcSecrets,
	},
	kindXRPL: {
		validate:   validateXRPLOptions,
		identity:   []string{"address"},
		classify:   classifyXRPL,
		shownValue: shownXRPLValue,
		stale:      staleNode,
		notes:      rpcNotes,
		secrets:    rpcSecrets,
	},
	kindWeb: {
		validate:     validateWebOptions,
		identity:     []string{"url"},
		checkInitial: checkInitialWeb,
		classify:     classifyWeb,
		stale:        staleNode,
		notes:        webNotes,
		reportNotes:  webReportNotes,
		warnings:     webWarnings,
		secrets:      webSecrets,
	},
	kindRepo: {
		validate:     validateRepoOptions,
		identity:     []string{"root"},
		checkInitial: checkInitialRepo,
		classify:     classifyRepo,
		stale:        staleNode,
	},
	kindPods: {
		validate:     validatePodsOptions,
		identity:     []string{"file"},
		checkInitial: checkInitialPods,
		classify:     classifyPods,
		describe:     describePods,
		foldedInto:   podsFoldedInto,
		stale:        staleFile,
		warnings:     podsWarnings,
	},
}

// rulesOf returns the rules of a kind. An unknown kind has none, and words a
// stale read the way the first kinds did.
func rulesOf(kind string) kindRules {
	r, ok := kinds[kind]
	if !ok {
		r.stale = staleNode
	}
	return r
}

// IdentityChanged reports whether old and now describe different targets of
// the kind: the address, type, page address, root or file differ.
func IdentityChanged(kind string, old, now Observation) bool {
	for _, f := range rulesOf(kind).identity {
		if old[f] != now[f] {
			return true
		}
	}
	return false
}

// CheckInitial is for an observation about to enter the baseline for the first
// time. A wrong address, type, root or file can read clean forever, so what
// points to one is refused here. It is not an error during check: a contract
// that later loses its code is a change.
func CheckInitial(t Target, obs Observation) error {
	if f := rulesOf(t.Kind).checkInitial; f != nil {
		return f(t, obs)
	}
	return nil
}

// TargetNotes are remarks on how a target is read. They name RPC addresses by
// position only.
func TargetNotes(t Target) []string {
	if f := rulesOf(t.Kind).notes; f != nil {
		return f(t)
	}
	return nil
}

// ReportNotes are remarks for a check report on what was read of a target,
// partial reads included. They are not findings and do not change the exit code.
func ReportNotes(t Target, obs Observation, changes []Change) []string {
	if f := rulesOf(t.Kind).reportNotes; f != nil {
		return f(t, obs, changes)
	}
	return nil
}

// BaselineWarnings are said by init and accept about what they take in.
func BaselineWarnings(t Target, obs Observation) []string {
	if f := rulesOf(t.Kind).warnings; f != nil {
		return f(t, obs)
	}
	return nil
}

// TargetSecrets are the values of a target's config that must not reach any
// output: RPC addresses held in the environment variables it names, and the
// values in the query of a web page's address.
func TargetSecrets(t Target) []string {
	if f := rulesOf(t.Kind).secrets; f != nil {
		return f(t)
	}
	return nil
}

// SingleRPCNote is the remark on a target whose answers cannot be cross-checked.
const SingleRPCNote = "RPC 주소가 하나뿐이거나 모두 같아 응답을 교차 확인하지 못했습니다. 이 RPC가 틀린 답을 주면 알아챌 수 없습니다."

const (
	plainHTTPNote     = "RPC %d의 주소는 암호화되지 않은 http입니다. 주고받는 내용과 주소에 든 키가 네트워크에서 보일 수 있습니다."
	plainHTTPPageNote = "페이지나 스크립트의 주소가 암호화되지 않은 http입니다. 주고받는 내용과 주소에 든 값이 네트워크에서 보일 수 있고, 받은 내용이 오는 길에 바뀔 수 있습니다."
	unreadNote        = "페이지의 스크립트 %d개는 allowed_hosts에 없는 호스트에 있어 내용을 읽지 않았습니다(not-fetched). 그 스크립트의 내용이 바뀌어도 알 수 없습니다. 믿는 호스트라면 allowed_hosts에 적으세요."
	outsideNote       = "컨테이너 %d개의 이미지가 allowed_registries 밖의 레지스트리에서 왔습니다(%s). 이 이미지는 점검할 때마다 WA-103으로 나오고, accept로는 없어지지 않습니다. 승인한 레지스트리라면 allowed_registries에 적고, 아니면 이미지를 고치세요."
	delegateNote      = "지금 위임 대상 %s이(가) allowed_delegates에 없습니다. 기준값은 처음 상태가 정상이라고 가정하므로, 이 위임이 승인된 것인지 확인하세요."
)

func rpcNotes(t Target) []string {
	var notes []string
	if SingleEndpoint(t) {
		notes = append(notes, SingleRPCNote)
	}
	for _, i := range PlainHTTPEndpoints(t) {
		notes = append(notes, fmt.Sprintf(plainHTTPNote, i))
	}
	return notes
}

func webNotes(t Target) []string {
	if PlainHTTPPage(t) {
		return []string{plainHTTPPageNote}
	}
	return nil
}

func webWarnings(_ Target, obs Observation) []string {
	if n := UnreadScripts(obs); n > 0 {
		return []string{fmt.Sprintf(unreadNote, n)}
	}
	return nil
}

func webReportNotes(t Target, obs Observation, _ []Change) []string { return webWarnings(t, obs) }

// evmWarnings says so when a baseline is taking in a delegate outside the allow
// list: check will stay clean about it from now on.
func evmWarnings(t Target, obs Observation) []string {
	if DelegateOutsideAllowList(t, obs) {
		return []string{fmt.Sprintf(delegateNote, obs["delegate"])}
	}
	return nil
}

func evmReportNotes(t Target, obs Observation, changes []Change) []string {
	if slices.ContainsFunc(changes, func(c Change) bool { return c.Key == t.Key && c.Field == "delegate" }) {
		return nil // that change is a finding already
	}
	return evmWarnings(t, obs)
}

// podsWarnings warns init and accept when what they take in has images from a
// registry outside allowed_registries: check will report them every time.
func podsWarnings(t Target, obs Observation) []string {
	out := OutsideAllowedRegistries(t, obs, nil)
	if len(out) == 0 {
		return nil
	}
	shown := out[:min(len(out), 3)]
	text := strings.Join(shown, ", ")
	if len(out) > len(shown) {
		text += " 등"
	}
	return []string{fmt.Sprintf(outsideNote, len(out), text)}
}

func rpcSecrets(t Target) []string {
	var out []string
	raw, _ := t.Options["rpc_url_env"].(string)
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			if !ValidEnvName(name) {
				out = append(out, name) // an address pasted where a name belongs
				continue
			}
			out = append(out, os.Getenv(name))
		}
	}
	return out
}

func webSecrets(t Target) []string {
	out := queryValues(t.Options["url"])
	if l, ok := t.Options["extra_scripts"].([]any); ok {
		for _, e := range l {
			out = append(out, queryValues(e)...)
		}
	}
	return out
}

// queryValues returns the values in the query of an address, those long
// enough to be told apart from ordinary text.
func queryValues(v any) []string {
	s, _ := v.(string)
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	var out []string
	for _, vs := range u.Query() {
		for _, q := range vs {
			if len(q) >= 6 {
				out = append(out, q)
			}
		}
	}
	return out
}

func classifyEVM(c Change, allowed map[string]bool) (verdict, bool) {
	switch c.Field {
	case "delegate":
		switch {
		case c.New == "":
			return verdict{"WA-006", finding.Medium, "기준값에 있던 위임이 지워졌습니다", "위임이 없는 것으로 읽힘"}, true
		case allowed[normAddr(c.New)]:
			return verdict{"WA-005", finding.Info, "허용 목록 안의 위임으로 바뀌었습니다", "허용 목록 안의 위임으로 읽힘"}, true
		}
		return verdict{"WA-001", finding.Critical, "허용 목록에 없는 위임이 생겼습니다", "허용 목록에 없는 위임으로 읽힘"}, true
	case "owners", "threshold", "admin":
		return verdict{"WA-002", finding.Critical, "소유자, 임계값 또는 관리자가 바뀌었습니다", "소유자, 임계값 또는 관리자가 다르게 읽힘"}, true
	case "master_copy", "implementation":
		return verdict{"WA-002", finding.Critical, "로직 컨트랙트가 교체되었습니다", "로직 컨트랙트가 다르게 읽힘"}, true
	case "code_sha256":
		return verdict{"WA-003", finding.High, "코드가 바뀌었습니다", "코드가 다르게 읽힘"}, true
	}
	return verdict{}, false
}

func classifyXRPL(c Change, _ map[string]bool) (verdict, bool) {
	switch c.Field {
	case "regular_key", "signer_list":
		return verdict{"WA-002", finding.Critical, "계정의 서명 권한(레귤러 키 또는 서명자 목록)이 바뀌었습니다", "서명 권한(" + c.Field + ")이 다르게 읽힘"}, true
	case "flags":
		// One number holds many settings: only one bit is about who can sign.
		return verdict{"WA-002", finding.Critical, "계정 플래그(flags)가 바뀌었습니다. 무해한 계정 설정일 수 있으니 마스터 키를 끄는 비트(lsfDisableMaster, 0x00100000)부터 확인하세요", "계정 플래그(flags)가 다르게 읽힘"}, true
	}
	return verdict{}, false
}

func shownXRPLValue(field, value string) string {
	if field == "flags" {
		return shownFlags(value)
	}
	return shown(value)
}

func classifyWeb(c Change, _ map[string]bool) (verdict, bool) {
	if strings.HasPrefix(c.Field, "script:") {
		return verdict{"WA-101", finding.High, "배포된 스크립트가 기준값과 다릅니다", "스크립트가 기준값과 다르게 읽힘"}, true
	}
	return verdict{}, false
}

func classifyRepo(c Change, _ map[string]bool) (verdict, bool) {
	if strings.HasPrefix(c.Field, "file:") {
		return verdict{"WA-102", finding.High, "저장소의 설정 파일이 기준값과 다릅니다", "저장소 파일이 기준값과 다르게 읽힘"}, true
	}
	return verdict{}, false
}

func classifyPods(c Change, _ map[string]bool) (verdict, bool) {
	if isImageField(c.Field) {
		return verdict{"WA-103", finding.High, "실행 중인 컨테이너 이미지가 기준값과 다릅니다", "기준값과 다른 컨테이너 이미지로 읽힘"}, true
	}
	return verdict{}, false
}

func describePods(c Change, obs Observation, t Target) (title, topic, extra string, ok bool) {
	if !isImageField(c.Field) {
		return "", "", "", false
	}
	title, topic, extra = describeImageChange(c, obs, podsAllowed(t))
	return title, topic, extra, true
}

// podsFoldedInto: an image and its registry are read as two fields. When both
// changed they are one finding, so the registry change is folded into the image one.
func podsFoldedInto(field string) string {
	if name, ok := strings.CutPrefix(field, registryField); ok {
		return imageField + name
	}
	return ""
}
