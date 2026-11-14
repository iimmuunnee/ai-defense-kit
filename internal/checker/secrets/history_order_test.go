package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// randomSecret makes a test value at run time, so no key-shaped string sits in
// the repository.
func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "T" + hex.EncodeToString(b)
}

func permutations(in []report.Finding) [][]report.Finding {
	if len(in) <= 1 {
		return [][]report.Finding{append([]report.Finding(nil), in...)}
	}
	var out [][]report.Finding
	for i := range in {
		rest := append(append([]report.Finding(nil), in[:i]...), in[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]report.Finding{in[i]}, p...))
		}
	}
	return out
}

// gitleaks는 과거 기록의 파일 변경을 병렬로 검사해서 결과 순서가 실행마다 다르다.
// 같은 키가 과거 기록 여러 곳에 있을 때 대표 위치와 지문은 그 순서와 상관없이 같아야 한다.
// 대표는 가장 오래된 커밋이고, 커밋 시각이 같으면 경로, 줄, 열, 커밋 순이다.
func TestHistoryRepresentativeIgnoresGitleaksOrder(t *testing.T) {
	secret := randomSecret(t)
	sha := func(c string) string { return strings.Repeat(c, 40) }
	at := func(file, commit, date string, line int) report.Finding {
		return report.Finding{RuleID: "generic-api-key", Secret: secret, File: file, Commit: commit,
			Date: date, StartLine: line, StartColumn: 1}
	}
	in := []report.Finding{
		at("a/new.env", sha("1"), "2021-03-01T00:00:00Z", 3),
		at("c/same-time.env", sha("2"), "2020-01-01T00:00:00Z", 1),
		at("b/old.env", sha("4"), "2020-01-01T00:00:00Z", 9),
		at("b/old.env", sha("3"), "2020-01-01T00:00:00Z", 9),
	}

	var want finding.Finding
	for n, p := range permutations(in) {
		got := merge("", nil, p, "", "")
		if len(got) != 1 {
			t.Fatalf("order %d: %d findings, want 1", n, len(got))
		}
		if n == 0 {
			want = got[0]
			if want.Location != "b/old.env" || !strings.Contains(want.Evidence, "(커밋 3333333)") {
				t.Fatalf("representative = %s %q, want b/old.env at the oldest commit with the smaller hash",
					want.Location, want.Evidence)
			}
			continue
		}
		if got[0].Location != want.Location || got[0].Evidence != want.Evidence || got[0].Fingerprint != want.Fingerprint {
			t.Fatalf("order %d: representative %s %q %s, first order gave %s %q %s", n,
				got[0].Location, got[0].Evidence, got[0].Fingerprint, want.Location, want.Evidence, want.Fingerprint)
		}
	}
}
