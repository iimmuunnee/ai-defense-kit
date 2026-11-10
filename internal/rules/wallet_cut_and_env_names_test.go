package rules

import (
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 값은 모두 시험 안에서 조립한다. 파일은 t.TempDir() 안에만 쓴다.

// 1. 근거와 지문은 앞 200글자만 쓴다. 키 모양이 200글자 경계를 넘으면 그 앞부분만 해시되므로,
// 지문은 그 모양을 표시로 바꾼 줄과 줄 번호에서 만든다. 앞 4글자만 다른 두 키는 같은 지문이다.
func TestFingerprintWithKeyCrossingTheCut(t *testing.T) {
	key := r4Key("cut-cross")
	other := "ffff" + key[4:]
	if other == key {
		other = "eeee" + key[4:]
	}
	line := func(k string) string {
		pre := "const k = import.meta.env.VITE_SECRET_KEY; const p = \""
		pad := strings.Repeat("x", maxEvidence-4-len([]rune(pre))) // 키의 첫 묶음이 200글자 안, 나머지는 밖
		return pre + pad + "/" + strings.Join(r4Groups(k), "/") + "\";"
	}
	a := scanText(t, "RE-001", "src/a.ts", line(key)+"\n", []string{"react"})
	b := scanText(t, "RE-001", "src/a.ts", line(other)+"\n", []string{"react"})
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("findings = %d, %d", len(a), len(b))
	}
	if a[0].Fingerprint != b[0].Fingerprint {
		t.Error("fingerprint depends on the first 4 characters of a key that crosses the cut")
	}
	if l := r4Leaks(a[0].Evidence, nil, key); len(l) > 0 {
		t.Errorf("evidence leaked %v", l)
	}
	// 줄이 옮겨 가도 지문은 같다(줄 번호는 지문에 들어가지 않는다).
	c := scanText(t, "RE-001", "src/a.ts", "\n"+line(key)+"\n", []string{"react"})
	if len(c) != 1 || c[0].Fingerprint != a[0].Fingerprint {
		t.Error("fingerprint moved with the line")
	}
	// 200글자 안에 다 들어가는 넓은 모양 줄의 지문도 보이는 근거에서 만들고 줄 전체의 해시가 아니다.
	short := "const k = import.meta.env.VITE_SECRET_KEY; const p = \"/" + strings.Join(r4Groups(key), "/") + "\";"
	s := scanText(t, "RE-001", "src/a.ts", short+"\n", []string{"react"})
	if len(s) != 1 || s[0].Fingerprint != finding.MakeMaskedFingerprint("RE-001", "src/a.ts", s[0].Evidence, 0) {
		t.Errorf("short line fingerprint: %+v", s)
	}
}

// 2. 환경 파일에서 이름 자리는 올바른 환경 변수 이름(앞에 export 가능)일 때만 보인다.
func TestEnvNameMustBeAValidName(t *testing.T) {
	six := r4Words[:6]
	for _, rel := range []string{".env", ".envrc", ".env-local"} {
		for _, line := range []string{
			strings.Join(six, "-") + "=x",
			strings.Join(six, ".") + "=x",
			"export " + strings.Join(six, "-") + "=x",
			strings.Join(six, " ") + " = x",
			`"` + strings.Join(six, "_") + `"=x`,
		} {
			got := maskEvidenceFor(rel, line)
			if got != "****" {
				t.Errorf("%s %q -> %q, want ****", rel, line, got)
			}
		}
		for line, want := range map[string]string{
			"VITE_SECRET_KEY=" + strings.Join(six, "-"):        "VITE_SECRET_KEY=****",
			"export VITE_SECRET_KEY=" + strings.Join(six, "-"): "export VITE_SECRET_KEY=****",
			"  _A1 = " + strings.Join(six, " "):                "  _A1 = ****",
		} {
			if got := maskEvidenceFor(rel, line); got != want {
				t.Errorf("%s %q -> %q, want %q", rel, line, got, want)
			}
		}
	}
}

// 3. %20, &#160;, &#xA0;, &nbsp; 같은 이스케이프도 단어 사이 구분 문자다.
func TestEscapedSeparatorsJoinWords(t *testing.T) {
	w := r4Words
	seps := []string{"%20", "%2F", "&#160;", "&#xA0;", "&nbsp;", "&amp;"}
	for _, sep := range seps {
		run := strings.Join(w, sep)
		for _, c := range []struct{ rel, line string }{
			{"src/a.ts", "x = " + run + ";"},
			{"src/a.ts", "const k = import.meta.env.VITE_SECRET_KEY; x = " + run + ";"},
			{"src/a.ts", `fetch("https://x.test/q?a=` + run + `");`},
			{"a.html", "<p>" + run + "</p>"},
			{"a.html", `<script src="https://cdn.example.test/a.js"></script> <p>` + run + `</p>`},
		} {
			got := maskEvidenceFor(c.rel, c.line)
			if l := r4Leaks(got, w, ""); len(l) > 0 {
				t.Errorf("%q %s -> %q: leaked %v", sep, c.rel, got, l)
			}
		}
		// 규칙을 거친 근거: 코드(RE-001)와 HTML 글자(WEB-001)
		got := scanText(t, "RE-001", "src/a.ts", "const k = import.meta.env.VITE_SECRET_KEY; x = "+run+";\n", []string{"react"})
		if len(got) != 1 {
			t.Fatalf("RE-001 findings = %d", len(got))
		}
		if l := r4Leaks(got[0].Evidence, w, ""); len(l) > 0 {
			t.Errorf("RE-001 %q: %q leaked %v", sep, got[0].Evidence, l)
		}
		got = scanText(t, "WEB-001", "a.html", `<script src="https://cdn.example.test/a.js"></script> <p>`+run+"</p>\n", nil)
		if len(got) != 1 {
			t.Fatalf("WEB-001 findings = %d", len(got))
		}
		if l := r4Leaks(got[0].Evidence, w, ""); len(l) > 0 {
			t.Errorf("WEB-001 %q: %q leaked %v", sep, got[0].Evidence, l)
		}
	}
	// 이스케이프가 끼어도 짧은 나열은 그대로다.
	if got := maskEvidenceFor("src/a.ts", "run(a%20b, c&nbsp;d);"); got != "run(a%20b, c&nbsp;d);" {
		t.Errorf("short escaped text changed: %q", got)
	}
}
