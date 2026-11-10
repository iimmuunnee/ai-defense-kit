package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// 값 하나(이름, 리터럴, 작업 이름 등)는 구분 문자가 섞여도, 대문자여도 나열로 센다.
func TestValueRuleJoinsAnySeparators(t *testing.T) {
	w := genWords("b3-value", 12)
	up := make([]string, len(w))
	for i, s := range w {
		up[i] = strings.ToUpper(s)
	}
	for name, v := range map[string]string{
		"upper snake": strings.Join(up, "_"),
		"mixed":       w[0] + "/" + strings.Join(w[1:], "-") + "@main",
		"halves":      strings.Join(w[:6], "-") + "/" + strings.Join(w[6:], "-") + "@v1",
		"dotted":      "public." + strings.Join(up[:6], ".") + "_" + strings.Join(up[6:], "_"),
	} {
		got := strings.ToLower(ScrubValue(v))
		for _, word := range w {
			if strings.Contains(got, word) {
				t.Errorf("%s: %q -> word shown", name, got)
				break
			}
		}
		if !ValueHasKeyMaterial(v) {
			t.Errorf("%s: not taken for key material", name)
		}
	}
	// 짧은 이름은 그대로다.
	for _, v := range []string{"deploy-to-aws-prod", "build-and-test", "order_item_refund_audit_log_entry", "actions/checkout@v4", "api.staging.example.com"} {
		if got := ScrubValue(v); got != v {
			t.Errorf("%q -> %q", v, got)
		}
	}
}

// RunAll의 마지막 그물은 좁은 모양(64자리 16진수, 공백·쉼표로 나눈 나열)만 본다.
// 도구가 만든 문장 안의 구분 문자는 세지 않는다.
func TestNarrowNetLeavesComposedSentences(t *testing.T) {
	for _, s := range []string{
		"AWS_ACCESS_KEY_ID (작업 deploy-to-aws-prod 단계 2 env)",
		"pull_request_target 워크플로의 actions/checkout이 ref로 github.event.pull_request.head를 씁니다 (작업 build-and-test 단계 2)",
		"RLS가 켜지지 않은 테이블: public.order_item_refund_audit_log_entry",
		"인증서 공개 기록에서 찾은 서브도메인: pay.admin.internal.corp.example.com",
	} {
		if got := ScrubNarrow(s); got != s {
			t.Errorf("%q -> %q", s, got)
		}
	}
	w := genWords("b3-narrow", 12)
	sum := sha256.Sum256([]byte("b3-narrow-key"))
	key := hex.EncodeToString(sum[:])
	for _, s := range []string{
		"t: " + strings.Join(w, " "),
		"t: " + strings.Join(w, ", "),
		"t: " + key,
		"t: " + key[:32] + "/" + key[32:],
	} {
		got := ScrubNarrow(s)
		for _, word := range w {
			if strings.Contains(got, word) {
				t.Errorf("%q: word shown", got)
				break
			}
		}
		if strings.Contains(got, key[:8]) || strings.Contains(got, key[40:48]) {
			t.Errorf("%q: key piece shown", got)
		}
		if !strings.Contains(got, "가림") {
			t.Errorf("%q: no note", got)
		}
	}
}
