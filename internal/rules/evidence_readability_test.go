package rules

import (
	"strings"
	"testing"
)

// I3: 식별자가 많은 코드 줄의 근거가 통째로 가려지지 않는다.
func TestIdentifierHeavyEvidenceIsReadable(t *testing.T) {
	// SB-003: 클라이언트 컴포넌트가 읽는 환경 변수 이름이 보여야 한다.
	got := scanText(t, "SB-003", "app/admin.tsx",
		"\"use client\";\nconst admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n",
		[]string{"nextjs"})
	if len(got) != 1 {
		t.Fatalf("SB-003 findings = %d", len(got))
	}
	ev := got[0].Evidence
	for _, want := range []string{"createClient(", "process.env.NEXT_PUBLIC_SUPABASE_URL", "process.env.SUPABASE_SERVICE_ROLE_KEY"} {
		if !strings.Contains(ev, want) {
			t.Errorf("SB-003 evidence %q lacks %q", ev, want)
		}
	}

	// KR-AUTH-001: 주소의 질의가 보여서 state가 빠진 것을 근거에서 알 수 있다.
	line := "    window.location.href = `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${process.env.NEXT_PUBLIC_KAKAO_CLIENT_ID}&redirect_uri=${process.env.NEXT_PUBLIC_KAKAO_REDIRECT_URI}`;"
	got = scanText(t, "KR-AUTH-001", "app/LoginButton.tsx", "export function Login() {\n"+line+"\n}\n", []string{"nextjs"})
	if len(got) != 1 {
		t.Fatalf("KR-AUTH-001 findings = %d", len(got))
	}
	ev = got[0].Evidence
	for _, want := range []string{"kauth.kakao.com/oauth/authorize?", "client_id=${process.env.NEXT_PUBLIC_KAKAO_CLIENT_ID}", "redirect_uri=${process.env.NEXT_PUBLIC_KAKAO_REDIRECT_URI}"} {
		if !strings.Contains(ev, want) {
			t.Errorf("KR-AUTH-001 evidence %q lacks %q", ev, want)
		}
	}
	if strings.Contains(ev, "state") || strings.Contains(ev, "가림") {
		t.Errorf("KR-AUTH-001 evidence %q", ev)
	}

	// 토스 SDK 호출 줄: 환경 변수 이름이 보인다.
	toss := `const toss = await loadTossPayments(process.env.NEXT_PUBLIC_TOSS_CLIENT_KEY!);`
	if ev := maskEvidenceFor("app/checkout/page.tsx", toss); !strings.Contains(ev, "process.env.NEXT_PUBLIC_TOSS_CLIENT_KEY!") || strings.Contains(ev, "가림") {
		t.Errorf("toss line -> %q", ev)
	}
}

// M2: MIME 형식인 속성 값(type="text/javascript")은 가리지 않는다.
func TestMIMETypeAttributeIsShown(t *testing.T) {
	got := scanText(t, "WEB-001", "views/layout.ejs", `<script type="text/javascript" src='https://cdn.example.test/a.js' async></script>`+"\n", nil)
	if len(got) != 1 {
		t.Fatalf("WEB-001 findings = %d", len(got))
	}
	if !strings.Contains(got[0].Evidence, `type="text/javascript"`) {
		t.Errorf("evidence %q", got[0].Evidence)
	}
	for _, mime := range []string{"application/json", "application/ld+json", "text/x-template", "image/svg+xml"} {
		line := `<script type="` + mime + `">`
		if ev := maskEvidenceFor("a.html", line); ev != line {
			t.Errorf("%q -> %q", line, ev)
		}
	}
	// MIME 모양이 아닌 값은 이전처럼 가린다.
	if ev := maskEvidenceFor("a.html", `<a data-x="textonly/abcdefgh1234">`); strings.Contains(ev, "abcdefgh1234") {
		t.Errorf("non-MIME value shown: %q", ev)
	}
}

// M3: 걸린 줄이 주석뿐이면 그렇게 적는다.
func TestCommentOnlyLineSaysSo(t *testing.T) {
	for _, c := range []struct{ rel, line string }{
		{"webhook.php", "// portone webhook"},
		{"a.ts", "  /* portone */"},
		{"a.py", "# portone"},
		{"a.html", "<!-- portone -->"},
	} {
		if got := maskEvidenceFor(c.rel, c.line); got != "(주석 줄에서 찾음, 내용 생략)" {
			t.Errorf("%s %q -> %q", c.rel, c.line, got)
		}
	}
	// 코드 뒤의 주석은 이전처럼 "(주석 생략)"이다.
	if got := maskEvidenceFor("a.ts", "run(); // portone"); got != "run(); (주석 생략)" {
		t.Errorf("code + comment -> %q", got)
	}
	got := scanText(t, "KR-PAY-002", "webhook.php", "<?php\n// portone webhook\n$sig = $_SERVER['HTTP_WEBHOOK_SIGNATURE'] ?? '';\n", []string{"php"})
	if len(got) == 0 {
		t.Fatal("KR-PAY-002: no finding")
	}
	if got[0].Evidence != "(주석 줄에서 찾음, 내용 생략)" {
		t.Errorf("KR-PAY-002 evidence %q", got[0].Evidence)
	}
}
