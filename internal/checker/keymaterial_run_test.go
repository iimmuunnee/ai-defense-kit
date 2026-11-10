package checker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 어느 검사기가 만든 결과든 리포트로 가기 전에 근거와 제목에서 좁은 키·구문 모양
// (64자리 이상 16진수, 공백·쉼표로 나눈 단어 나열)을 가린다. 다른 구분 문자로 이은
// 모양은 저장소에서 온 이름을 넣는 검사기가 그 이름에서 먼저 가린다(도구가 만든 문장은
// 세지 않으려고). 지문은 검사기가 만든 그대로다. 값은 시험 안에서 조립한다.
func TestRunAllScrubsKeyMaterialFromEveryChecker(t *testing.T) {
	words := append([]string{"zoo", "quartz", "vessel", "amber", "lemur", "tunnel"},
		"glide", "pencil", "walnut", "bison", "cobalt", "oyster")
	sum := sha256.Sum256([]byte("run-canary-r5"))
	key := hex.EncodeToString(sum[:])
	c := fake{"x", func(context.Context, Target) (Result, error) {
		return Result{Findings: []finding.Finding{
			{ID: "A", Evidence: "public. " + strings.Join(words, " "), Title: "t: " + strings.Join(words, ", "), Fingerprint: "f1"},
			{ID: "B", Evidence: "uses: " + key[:32] + "/" + key[32:] + "@main", Title: "plain", Fingerprint: "f2"},
			{ID: "C", Evidence: "npm run build", Title: "ordinary", Fingerprint: "f3"},
		}}, nil
	}}
	got, _ := RunAll(context.Background(), []Checker{c}, Target{}, 0)
	if len(got) != 3 {
		t.Fatalf("findings = %d", len(got))
	}
	for _, f := range got {
		text := strings.ToLower(f.Evidence + " " + f.Title)
		for _, w := range words {
			if strings.Contains(text, w) {
				t.Errorf("%s: word %q shown: %q", f.ID, w, text)
			}
		}
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(text, key[i:i+4]) {
				t.Errorf("%s: key piece shown: %q", f.ID, text)
				break
			}
		}
	}
	if got[2].Evidence != "npm run build" || got[2].Title != "ordinary" {
		t.Errorf("ordinary finding changed: %+v", got[2])
	}
	for i, fp := range []string{"f1", "f2", "f3"} {
		if got[i].Fingerprint != fp {
			t.Errorf("fingerprint changed: %s", got[i].Fingerprint)
		}
	}
}
