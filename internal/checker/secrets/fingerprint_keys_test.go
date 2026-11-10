package secrets

import (
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// fingerprintsFor builds findings the way Run does and numbers the repeats.
func fingerprintsFor(fs []report.Finding) []finding.Finding {
	var out []finding.Finding
	var pos [][2]int
	for _, g := range fs {
		out = append(out, build(g, "secret-current", g.File, finding.Medium, "t", g.Secret, "", "", ""))
		pos = append(pos, [2]int{g.StartLine, g.StartColumn})
	}
	numberRepeats(out, pos)
	return out
}

func one(secret string, line int) string {
	g := report.Finding{RuleID: "generic-api-key", Secret: secret, StartLine: line, StartColumn: 1, File: "a/.env"}
	return fingerprintsFor([]report.Finding{g})[0].Fingerprint
}

// 지문에는 값의 어느 부분도 들어가지 않는다. 보이는 근거(앞 4자와 ****)가 같으면 값이 달라도
// 지문이 같고, 줄이 옮겨 가도 같다. 접두사를 해시에 넣으면 공개된 지문에서 무차별 대입으로 알아낼 수 있다.
func TestSecretFingerprintDependsOnlyOnShownEvidence(t *testing.T) {
	if one("sk_"+"live_abcdef123456", 9) != one("sk_"+"live_zzzzzzzzzzzz", 9) {
		t.Error("fingerprint depends on the part of the value that is not shown")
	}
	if one("sk_"+"live_abcdef123456", 9) != one("sk_"+"live_abcdef123456", 40) {
		t.Error("fingerprint moves with the line")
	}
	if one("sk_"+"live_abcdef123456", 9) == one("pk_"+"live_abcdef123456", 9) {
		t.Error("shown prefix must affect the fingerprint")
	}
}

// 개인 키나 시드 구문 모양의 값은 근거가 ****뿐이라 값이 달라도 지문이 같다.
func TestKeyShapedSecretFingerprintHasNoValue(t *testing.T) {
	rest := strings.Repeat("c3d4", 15)
	a, b := "0xaa"+rest+"e5f6", "0xbb"+rest+"e5f6"
	if one(a, 3) != one(b, 3) {
		t.Error("fingerprint depends on the first 4 characters of a key")
	}
	words := func(first string) string {
		// 구문은 시험 안에서 이어 붙인다(한 줄에 구문 모양을 적지 않게).
		rest := append([]string{"quartz", "vessel", "amber", "robot", "tunnel"},
			"glide", "pencil", "north", "spring", "cabin", "onion")
		return first + " " + strings.Join(rest, " ")
	}
	if one(words("zoo"), 5) != one(words("fox"), 5) {
		t.Error("fingerprint depends on the first words of a phrase")
	}
}

// 같은 파일에서 같은 규칙, 같은 근거가 반복되면 줄 순서(같은 줄이면 열 순서)대로 순번이 붙어
// 서로 다른 지문이 되고, 결과가 들어오는 순서와 다른 비밀 값의 유무에는 영향받지 않는다.
func TestRepeatedEvidenceGetsOrderNumbers(t *testing.T) {
	k1 := "0xaa" + strings.Repeat("c3d4", 15) + "e5f6"
	k2 := "0xbb" + strings.Repeat("d4c3", 15) + "f6e5"
	mk := func(rule, secret string, col int) report.Finding {
		return report.Finding{RuleID: rule, Secret: secret, StartLine: 7, StartColumn: col, File: "a/.env"}
	}
	other := mk("stripe-access-token", "sk_"+"live_abcdef123456", 50)
	lines := [][]report.Finding{
		{mk("generic-api-key", k1, 10), mk("generic-api-key", k2, 90), other},
		{other, mk("generic-api-key", k2, 90), mk("generic-api-key", k1, 10)},
		{mk("generic-api-key", k2, 90), other, mk("generic-api-key", k1, 10)},
		{mk("generic-api-key", k2, 90), mk("generic-api-key", k1, 10)},
	}
	for n, fs := range lines {
		got := map[int]string{}
		for i, f := range fingerprintsFor(fs) {
			if fs[i].RuleID == "generic-api-key" {
				got[fs[i].StartColumn] = f.Fingerprint
			}
		}
		if got[10] == got[90] {
			t.Fatalf("order %d: two repeats share a fingerprint", n)
		}
		if got[10] != one(k1, 7) {
			t.Errorf("order %d: the first repeat's fingerprint changed", n)
		}
	}
}
