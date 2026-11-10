package watch

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
)

const (
	delA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	delB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func walletCfg(allowed ...any) Config {
	opts := map[string]any{}
	if allowed != nil {
		opts["allowed_delegates"] = allowed
	}
	return Config{Targets: []Target{{Key: "w", Kind: "evm-wallet", Options: opts}}}
}

func one(t *testing.T, o Outcome, cfg Config) finding.Finding {
	t.Helper()
	got := Findings(o, cfg, nil)
	if len(got) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	return got[0]
}

func TestFindingsSeverityTable(t *testing.T) {
	cases := []struct {
		name   string
		allow  []any
		change Change
		id     string
		sev    finding.Severity
	}{
		{"delegate outside allow list", nil, Change{Key: "w", Field: "delegate", Old: "", New: delA}, "WA-001", finding.Critical},
		{"delegate outside non-empty allow list", []any{delB}, Change{Key: "w", Field: "delegate", Old: "", New: delA}, "WA-001", finding.Critical},
		{"delegate swapped to another unlisted", []any{delB}, Change{Key: "w", Field: "delegate", Old: delB, New: delA}, "WA-001", finding.Critical},
		{"delegate inside allow list", []any{delA}, Change{Key: "w", Field: "delegate", Old: "", New: delA}, "WA-005", finding.Info},
		{"allow list compared ignoring case", []any{strings.ToUpper(delA[2:])}, Change{Key: "w", Field: "delegate", Old: "", New: delA}, "WA-005", finding.Info},
		{"allow list with 0x and mixed case", []any{"0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa"}, Change{Key: "w", Field: "delegate", Old: "", New: delA}, "WA-005", finding.Info},
		{"delegate removed", nil, Change{Key: "w", Field: "delegate", Old: delA, New: ""}, "WA-006", finding.Medium},
		{"delegate removed, allow list or not", []any{delA}, Change{Key: "w", Field: "delegate", Old: delA, New: ""}, "WA-006", finding.Medium},
		{"owners", nil, Change{Key: "w", Field: "owners", Old: delA, New: delB}, "WA-002", finding.Critical},
		{"threshold", nil, Change{Key: "w", Field: "threshold", Old: "2", New: "1"}, "WA-002", finding.Critical},
		{"admin", nil, Change{Key: "w", Field: "admin", Old: delA, New: delB}, "WA-002", finding.Critical},
		{"code_sha256", nil, Change{Key: "w", Field: "code_sha256", Old: "a", New: "b"}, "WA-003", finding.High},
		{"implementation", nil, Change{Key: "w", Field: "implementation", Old: delA, New: delB}, "WA-002", finding.Critical},
		{"master_copy", nil, Change{Key: "w", Field: "master_copy", Old: delA, New: delB}, "WA-002", finding.Critical},
		{"address", nil, Change{Key: "w", Field: "address", Old: delA, New: delB}, "WA-007", finding.High},
		{"type", nil, Change{Key: "w", Field: "type", Old: "eoa", New: "safe"}, "WA-007", finding.High},
		{"unknown field defaults to WA-003", nil, Change{Key: "w", Field: "something_new", Old: "1", New: "2"}, "WA-003", finding.High},
		{"chain_id is not dropped", nil, Change{Key: "w", Field: "chain_id", Old: "1", New: "2"}, "WA-003", finding.High},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := one(t, Outcome{Changes: []Change{c.change}}, walletCfg(c.allow...))
			if f.ID != c.id || f.Kind != c.id || f.Severity != c.sev {
				t.Errorf("got %s/%s/%s, want %s/%s", f.ID, f.Kind, f.Severity, c.id, c.sev)
			}
			if f.Confidence != finding.Certain {
				t.Errorf("confidence = %q", f.Confidence)
			}
			if f.Location != "w" || !strings.Contains(f.Evidence, c.change.Field) || f.Title == "" || f.Fingerprint == "" {
				t.Errorf("finding = %+v", f)
			}
			if f.Source != "watch" {
				t.Errorf("source = %q", f.Source)
			}
		})
	}
}

func TestFindingsAllowListIsPerTarget(t *testing.T) {
	cfg := Config{Targets: []Target{
		{Key: "a", Kind: "evm-wallet", Options: map[string]any{"allowed_delegates": []any{delA}}},
		{Key: "b", Kind: "evm-wallet"},
	}}
	o := Outcome{Changes: []Change{
		{Key: "a", Field: "delegate", New: delA},
		{Key: "b", Field: "delegate", New: delA},
	}}
	sev := map[string]finding.Severity{}
	for _, f := range Findings(o, cfg, nil) {
		sev[f.Location] = f.Severity
	}
	if sev["a"] != finding.Info || sev["b"] != finding.Critical {
		t.Errorf("severities = %v", sev)
	}
}

func TestFindingsAllowListAsStringSlice(t *testing.T) {
	cfg := Config{Targets: []Target{{Key: "w", Kind: "evm-wallet", Options: map[string]any{"allowed_delegates": []string{delA}}}}}
	f := one(t, Outcome{Changes: []Change{{Key: "w", Field: "delegate", New: delA}}}, cfg)
	if f.Severity != finding.Info {
		t.Errorf("severity = %s", f.Severity)
	}
}

// A Change is never dropped, whatever its field is called.
func TestFindingsNeverDropsAChange(t *testing.T) {
	fields := []string{"delegate", "owners", "threshold", "admin", "code_sha256", "implementation",
		"master_copy", "chain_id", "", "x", "Delegate", "unknown field", "한글"}
	var o Outcome
	for i, f := range fields {
		o.Changes = append(o.Changes, Change{Key: "w", Field: f, Old: fmt.Sprint(i), New: fmt.Sprint(i + 1)})
		o.Changes = append(o.Changes, Change{Key: "unconfigured", Field: f, Old: "", New: "n"})
	}
	got := Findings(o, walletCfg(), nil)
	if len(got) != len(o.Changes) {
		t.Fatalf("%d changes gave %d findings", len(o.Changes), len(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		if f.ID == "" {
			t.Errorf("finding without id: %+v", f)
		}
		if seen[f.Fingerprint] {
			t.Errorf("duplicate fingerprint %s", f.Fingerprint)
		}
		seen[f.Fingerprint] = true
	}
}

func TestFindingsDisagreement(t *testing.T) {
	o := Outcome{
		Unverified: map[string]string{"w": "RPC 응답이 서로 다릅니다", "x": "연결하지 못했습니다"},
		Disagreed:  []string{"w"},
	}
	f := one(t, o, walletCfg())
	if f.ID != "WA-004" || f.Severity != finding.High || f.Location != "w" || f.Confidence != finding.Certain {
		t.Errorf("finding = %+v", f)
	}
	if got := Findings(Outcome{Unverified: map[string]string{"x": "연결하지 못했습니다"}}, walletCfg(), nil); len(got) != 0 {
		t.Errorf("a plain unverified target must not be a finding: %+v", got)
	}
}

func TestFindingsNothingToReport(t *testing.T) {
	o := Outcome{NewTargets: []string{"n"}, RemovedTargets: []string{"r"}}
	if got := Findings(o, walletCfg(), nil); len(got) != 0 {
		t.Errorf("findings = %+v", got)
	}
}

func TestFindingsTextFromData(t *testing.T) {
	data := fstest.MapFS{}
	for _, n := range []string{"1", "2", "3", "4", "5"} {
		data["explain/WA-00"+n+".md"] = &fstest.MapFile{Data: []byte("설명 " + n)}
		data["fixes/WA-00"+n+"/watch.md"] = &fstest.MapFile{Data: []byte("대응 " + n)}
	}
	o := Outcome{
		Changes: []Change{
			{Key: "w", Field: "delegate", New: delA}, {Key: "w", Field: "owners", Old: "a", New: "b"},
			{Key: "w", Field: "code_sha256", Old: "a", New: "b"},
		},
		Unverified: map[string]string{"w": "x"}, Disagreed: []string{"w"},
	}
	got := Findings(o, walletCfg(), data)
	if len(got) != 4 {
		t.Fatalf("findings = %+v", got)
	}
	for _, f := range got {
		n := f.ID[len(f.ID)-1:]
		if f.ExplainKo != "설명 "+n || f.Fix != "대응 "+n {
			t.Errorf("%s: explain=%q fix=%q", f.ID, f.ExplainKo, f.Fix)
		}
	}
}

func TestFindingsNilDataLeavesTextEmpty(t *testing.T) {
	f := one(t, Outcome{Changes: []Change{{Key: "w", Field: "owners", New: "b"}}}, walletCfg())
	if f.ExplainKo != "" || f.Fix != "" {
		t.Errorf("finding = %+v", f)
	}
}

func TestFindingsFingerprintsDiffer(t *testing.T) {
	o := Outcome{Changes: []Change{
		{Key: "b", Field: "owners", New: "1"}, {Key: "a", Field: "owners", New: "1"},
	}}
	a := Findings(o, Config{}, nil)
	if len(a) != 2 || a[0].Fingerprint == a[1].Fingerprint {
		t.Errorf("findings = %+v", a)
	}
}

// The Info case (an allowed delegate) must never carry the text written for a
// delegation outside the allow list.
func TestInfoDelegateFindingsDoNotCarryWA001Text(t *testing.T) {
	data := fstest.MapFS{}
	for _, n := range []string{"1", "5"} {
		data["explain/WA-00"+n+".md"] = &fstest.MapFile{Data: []byte("설명 " + n)}
		data["fixes/WA-00"+n+"/watch.md"] = &fstest.MapFile{Data: []byte("대응 " + n)}
	}
	c := Change{Key: "w", Field: "delegate", New: delA}
	got := Findings(Outcome{Changes: []Change{c}}, walletCfg(delA), data)
	if len(got) != 1 || got[0].ID != "WA-005" || got[0].ExplainKo != "설명 5" || got[0].Fix != "대응 5" {
		t.Errorf("allowed: %+v", got)
	}
	got = Findings(Outcome{Changes: []Change{{Key: "w", Field: "delegate", New: delB}}}, walletCfg(delA), data)
	if len(got) != 1 || got[0].ID != "WA-001" || got[0].ExplainKo != "설명 1" {
		t.Errorf("unlisted: %+v", got)
	}
}

// Every id this package can report has its texts and is in the catalog.
func TestWatchIDsHaveTextsAndCatalogEntry(t *testing.T) {
	for _, id := range []string{"WA-001", "WA-002", "WA-003", "WA-004", "WA-005", "WA-006", "WA-007"} {
		for _, p := range []string{"../../explain/" + id + ".md", "../../fixes/" + id + "/watch.md"} {
			if b, err := os.ReadFile(p); err != nil || strings.TrimSpace(string(b)) == "" {
				t.Errorf("%s: %v", p, err)
			}
		}
		if !slices.Contains(mapping.BuiltinKinds, id) {
			t.Errorf("%s is not in mapping.BuiltinKinds", id)
		}
	}
}

// The texts must say what the new severities mean.
func TestLogicContractTexts(t *testing.T) {
	e2 := readText(t, "../../explain/WA-002.md")
	for _, s := range []string{"master_copy", "implementation", "로직 컨트랙트", "지갑을 통제"} {
		if !strings.Contains(e2, s) {
			t.Errorf("explain/WA-002.md lacks %q", s)
		}
	}
	for _, p := range []string{"../../explain/WA-003.md", "../../fixes/WA-003/watch.md"} {
		s := readText(t, p)
		for _, bad := range []string{"master_copy", "`implementation`"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s still describes %s", p, bad)
			}
		}
	}
	if !strings.Contains(readText(t, "../../explain/WA-007.md"), "다른 대상") {
		t.Errorf("explain/WA-007.md does not say the baseline describes another target")
	}
}

func readText(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Error(err)
	}
	return string(b)
}

// I8, I4: the texts are written for an operations or security responder and
// state only what the tool knows.
func TestResponderTexts(t *testing.T) {
	ids := []string{"WA-001", "WA-002", "WA-003", "WA-004", "WA-005", "WA-006", "WA-007"}
	for _, id := range ids {
		for _, p := range []string{"../../explain/" + id + ".md", "../../fixes/" + id + "/watch.md"} {
			s := readText(t, p)
			for _, bad := range []string{"본인", "거래소나 수탁 업체를 쓴다면", "막는다", "안전", "방어한다", "새어 나갔다고 보고"} {
				if strings.Contains(s, bad) {
					t.Errorf("%s contains %q", p, bad)
				}
			}
		}
	}
	must := func(p string, words ...string) {
		t.Helper()
		s := readText(t, p)
		for _, w := range words {
			if !strings.Contains(s, w) {
				t.Errorf("%s lacks %q", p, w)
			}
		}
	}
	mustNot := func(p string, words ...string) {
		t.Helper()
		s := readText(t, p)
		for _, w := range words {
			if strings.Contains(s, w) {
				t.Errorf("%s still says %q", p, w)
			}
		}
	}
	for _, p := range []string{"../../explain/WA-001.md", "../../fixes/WA-001/watch.md"} {
		must(p, "서명 경로", "0 주소", "토큰 승인", "증거")
	}
	must("../../explain/WA-001.md", "어떤 계정이든")
	mustNot("../../explain/WA-001.md", "키 소유자만 보낼 수")
	mustNot("../../explain/WA-004.md", "우연이라고 보기 어렵습니다", "종료 코드는 1입니다")
	must("../../explain/WA-004.md", "--fail-on")
	must("../../explain/WA-002.md", "UUPS")
	mustNot("../../explain/WA-005.md", "위험하다고 볼 근거", "평범한 계정으로 돌아갔다", "긴급 상황을 뜻하지는", "사라졌")
	must("../../explain/WA-006.md", "토큰 승인", "과거 거래", "누가")
	must("../../fixes/WA-006/watch.md", "토큰 승인", "과거 거래")
}

// "Asked twice, the same" reads as "they matched". It means they differed both times.
func TestDisagreementEvidenceSaysTheyDiffered(t *testing.T) {
	f := one(t, Outcome{Unverified: map[string]string{"w": "x"}, Disagreed: []string{"w"}}, walletCfg())
	if strings.Contains(f.Evidence, "같았습니다") || !strings.Contains(f.Evidence, "두 번 모두 달랐습니다") {
		t.Errorf("evidence = %q", f.Evidence)
	}
}

func TestBuiltinWA005Text(t *testing.T) {
	for _, p := range []string{"../../explain/WA-005.md", "../../fixes/WA-005/watch.md"} {
		b, err := os.ReadFile(p)
		if err != nil || strings.Contains(string(b), "allowed_delegates`에 없습니다") {
			t.Errorf("%s: %v", p, err)
		}
	}
}
