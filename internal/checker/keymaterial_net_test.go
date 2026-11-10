package checker

import (
	"context"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// I1: 마지막 그물은 도구가 만든 문장(한국어 설명, 하이픈 이름, 점으로 이은 이름)을
// 단어 나열로 세지 않는다.
func TestRunAllLeavesComposedSentences(t *testing.T) {
	want := []finding.Finding{
		{ID: "CI-001", Evidence: "AWS_ACCESS_KEY_ID (작업 deploy-to-aws-prod 단계 2 env)", Title: "장기 클라우드 키를 워크플로에 직접 넣은 설정", Fingerprint: "f1"},
		{ID: "CI-004", Evidence: "pull_request_target 워크플로의 actions/checkout이 ref로 github.event.pull_request.head를 씁니다 (작업 build-and-test 단계 2)", Title: "pull_request_target에서 PR의 코드를 내려받는 체크아웃", Fingerprint: "f2"},
		{ID: "SB-001", Evidence: "public.order_item_refund_audit_log_entry", Title: "RLS가 켜지지 않은 테이블: public.order_item_refund_audit_log_entry", Fingerprint: "f3"},
		{ID: "AS-002", Evidence: "인증서 1개, 처음 발급 2026-11-20, 마지막 만료 2027-02-18, 지금 유효한 인증서 없음 (소유 미확인)", Title: "인증서 공개 기록에서 찾은 서브도메인: pay.admin.internal.corp.example.com", Fingerprint: "f4"},
	}
	c := fake{"x", func(context.Context, Target) (Result, error) {
		return Result{Findings: append([]finding.Finding(nil), want...)}, nil
	}}
	got, _ := RunAll(context.Background(), []Checker{c}, Target{}, 0)
	if len(got) != len(want) {
		t.Fatalf("findings = %d", len(got))
	}
	for i := range want {
		if got[i].Evidence != want[i].Evidence || got[i].Title != want[i].Title {
			t.Errorf("%s: evidence %q title %q", want[i].ID, got[i].Evidence, got[i].Title)
		}
	}
}
