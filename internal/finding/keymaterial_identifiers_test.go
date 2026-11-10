package finding

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// 시험용 단어는 해시에서 시험 안에서 만든다(파일에 단어 나열을 적지 않는다).
// 6글자 영문 소문자라 출력의 다른 글자와 우연히 겹치기 어렵다.
func genWords(seed string, n int) []string {
	var out []string
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256([]byte(seed + string(rune('a'+i%26)) + strings.Repeat("x", i/26)))
		w := make([]byte, 6)
		for j := range w {
			w[j] = 'a' + sum[j]%26
		}
		out = append(out, string(w))
	}
	return out
}

func title(w string) string { return strings.ToUpper(w[:1]) + w[1:] }

// I3: 식별자가 많은 코드 줄은 글 규칙(텍스트 규칙)에서 단어 나열이 아니다.
func TestTextRuleKeepsIdentifierHeavyCode(t *testing.T) {
	w := genWords("b3-text-keep", 12)
	up := make([]string, len(w))
	camel := w[0]
	for i, s := range w {
		up[i] = strings.ToUpper(s)
		if i > 0 {
			camel += title(s)
		}
	}
	for _, line := range []string{
		`const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
		`const toss = await loadTossPayments(process.env.NEXT_PUBLIC_TOSS_CLIENT_KEY!);`,
		"window.location.href = `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${process.env.NEXT_PUBLIC_KAKAO_CLIENT_ID}&redirect_uri=${process.env.NEXT_PUBLIC_KAKAO_REDIRECT_URI}`;",
		"run(" + strings.Join(up, "_") + ");", // UPPER_SNAKE
		"run(" + camel + ");",                 // camelCase
		"run(" + strings.Join(w[:6], "/") + "-" + strings.Join(w[6:], "-") + ");", // 섞인 구분 문자
		"x = a." + strings.Join(w[:5], ".") + "_" + strings.Join(w[5:], "_") + ";",
		"call(" + strings.Join(up, ".") + ");", // 대문자 점 모양
	} {
		if got := ScrubKeyMaterial(line); got != line {
			t.Errorf("%q -> %q, want unchanged", line, got)
		}
		if ContainsKeyMaterial(line) {
			t.Errorf("%q taken for key material", line)
		}
	}
}

// 공백·쉼표로 나눈 나열(대소문자 무관, 번호 가능)과, 한 가지 구분 문자로만 이은
// 영문 소문자 나열은 그대로 가린다.
func TestTextRuleStillHidesPhraseShapes(t *testing.T) {
	w := genWords("b3-text-hide", 12)
	up := make([]string, len(w))
	num := make([]string, len(w))
	for i, s := range w {
		up[i] = strings.ToUpper(s)
		num[i] = string(rune('1'+i%9)) + ". " + s
	}
	shapes := map[string]string{
		"spaces":   strings.Join(w, " "),
		"upper":    strings.Join(up, " "),
		"commas":   strings.Join(w, ", "),
		"numbered": strings.Join(num, " "),
		"slash":    strings.Join(w, "/"),
		"under":    strings.Join(w, "_"),
		"dash":     strings.Join(w, "-"),
		"dot":      strings.Join(w, "."),
		"pipe":     strings.Join(w, "|"),
		"colon":    strings.Join(w, ":"),
		"semi":     strings.Join(w, ";"),
		"plus":     strings.Join(w, "+"),
		"pct20":    strings.Join(w, "%20"),
		"nbsp":     strings.Join(w, "&nbsp;"),
		"ent160":   strings.Join(w, "&#160;"),
	}
	for name, s := range shapes {
		for _, line := range []string{s, `x = "` + s + `";`, "f(" + s + ")"} {
			got := strings.ToLower(ScrubKeyMaterial(line))
			for _, word := range w {
				if strings.Contains(got, word) {
					t.Errorf("%s: %q -> word shown", name, got)
					break
				}
			}
		}
	}
}
