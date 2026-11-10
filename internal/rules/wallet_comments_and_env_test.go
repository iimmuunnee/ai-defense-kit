package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// r3HexGroups는 해시에서 만든 16진수를 4자리씩 공백으로 나눈 n묶음이다(시험 안에서 만든다).
func r3HexGroups(seed string, n int) string {
	sum := sha256.Sum256([]byte(seed))
	h := hex.EncodeToString(sum[:])
	var g []string
	for i := 0; i < n; i++ {
		g = append(g, h[i*4:i*4+4])
	}
	return strings.Join(g, " ")
}

// maskStallLimit는 느려졌는지 가리는 상한이다. 걸린 시간을 재는 값이 아니라
// 멈춘 것처럼 오래 걸리는 경우만 실패로 보려는 값이며, 느린 CI에서도 흔들리지 않도록
// internal/checker/secrets/masktext_test.go의 maskStallLimit과 같게 15초로 둔다.
const maskStallLimit = 15 * time.Second

// 근거에는 주석이 나오지 않는다. 파일 종류에 따라 주석 표시가 다르다.
func TestCommentsAreNeverPrinted(t *testing.T) {
	cases := []struct{ rel, line, keep string }{
		{"src/a.ts", "foo(1); // zoo quartz vessel", "foo(1);"},
		{"src/a.ts", "const a = 1; /* zoo quartz vessel", "const a ="},
		{"src/a.ts", "a /* zoo quartz */ b", "a"},
		{"src/a.tsx", "run(); // zoo - quartz | vessel ; amber / robot", "run();"},
		{"a.go", "x := 1 // zoo quartz", "x := 1"},
		{"a.py", "x = 1  # zoo quartz vessel", "x ="},
		{"a.rb", "x = 1 # zoo quartz", "x ="},
		{"a.sh", "run # zoo quartz", "run"},
		{".env", "# zoo quartz vessel", ""},
		{".env.local", "   # zoo quartz vessel", ""},
		{"a.yaml", "key: v # zoo quartz", "key:"},
		{"a.yml", "key: v   # zoo quartz", "key:"},
		{"a.html", "<p>x</p> <!-- zoo quartz vessel -->", "<p>x</p>"},
		{"a.ejs", "<p>x</p> <!-- zoo quartz", "<p>x</p>"},
		{"a.php", "echo 1; // zoo quartz", "echo 1;"},
		{"a.php", "echo 1; # zoo quartz", "echo 1;"},
		{"a.php", "echo 1; /* zoo quartz", "echo 1;"},
		{"a.vue", "run(); // zoo quartz", "run();"},
		{"a.sql", "select 1 -- zoo quartz", "select 1"},
		{"a.unknown", "a = 1 // zoo quartz", "a ="},
		{"a.unknown", "a = 1 # zoo quartz", "a ="},
		{"a.unknown", "a = 1 /* zoo quartz", "a ="},
		{"a.unknown", "a = 1 <!-- zoo quartz", "a ="},
		{"noext", "a = 1 // zoo quartz", "a ="},
	}
	for _, c := range cases {
		got := maskEvidenceFor(c.rel, c.line)
		if strings.Contains(got, "zoo") || strings.Contains(got, "quartz") || strings.Contains(got, "vessel") {
			t.Errorf("%s %q -> %q: comment text printed", c.rel, c.line, got)
		}
		if !strings.Contains(got, commentMarker) {
			t.Errorf("%s %q -> %q: no marker", c.rel, c.line, got)
		}
		if c.keep != "" && !strings.Contains(got, c.keep) {
			t.Errorf("%s %q -> %q: lost %q", c.rel, c.line, got, c.keep)
		}
	}
}

func TestNotCommentsStayAsTheyWere(t *testing.T) {
	cases := []struct{ rel, line string }{
		{"src/a.ts", `const u = "https://example.test/a#b"; fetch(u);`},
		{"src/a.ts", "this.#count = 1;"},
		{"src/a.ts", "const u = https://example.test/a;"},
		{"a.yaml", "url: https://example.test/p#frag"},
		{"a.html", "<script src=https://cdn.example.test/a.js></script>"},
		{"a.html", "<script src=//cdn.example.test/a.js></script>"},
		{"a.html", `<script src="https://cdn.example.test/a.js"></script>`},
	}
	for _, c := range cases {
		if got := maskEvidenceFor(c.rel, c.line); strings.Contains(got, commentMarker) {
			t.Errorf("%s %q -> %q: treated as a comment", c.rel, c.line, got)
		}
	}
	// 주석 표시는 따옴표와 상관없이 찾으므로 문자열 안의 표시도 주석으로 자른다(더 가리는 쪽).
	for _, c := range []struct{ rel, line string }{
		{"src/a.ts", `const s = "x // y";`},
		{"a.php", `echo "a # b";`},
		{"a.py", `s = "a # b"`},
	} {
		if got := maskEvidenceFor(c.rel, c.line); !strings.Contains(got, commentMarker) {
			t.Errorf("%s %q -> %q: marker inside a string not cut", c.rel, c.line, got)
		}
	}
}

// .env 파일은 값 전체를 가린다. 모양과 상관없다.
func TestEnvValuesAreMaskedWhole(t *testing.T) {
	vals := []string{
		// 12단어 구문은 시험 안에서 이어 붙인다(한 줄에 구문 모양을 적지 않게).
		strings.Join(append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
			"glide", "pencil", "north", "spring", "cabin", "onion"), ";"),
		"zoo - quartz | vessel / amber",
		"zoo quartz vessel",
		r3HexGroups("r3-env", 8),
		"'quoted value'",
		`"quoted value" # comment words`,
		"plain",
		"abc#def",
		"https://user:pw@example.test/p?x=1",
		"short",
	}
	for _, rel := range []string{".env", ".env.local", "app/.env.production", "config/.env"} {
		for _, v := range vals {
			if got := maskEvidenceFor(rel, "VITE_SECRET_KEY="+v); got != "VITE_SECRET_KEY=****" {
				t.Errorf("%s %q -> %q", rel, v, got)
			}
			if got := maskEvidenceFor(rel, "export VITE_SECRET_KEY = "+v); got != "export VITE_SECRET_KEY = ****" {
				t.Errorf("%s export %q -> %q", rel, v, got)
			}
		}
	}
	if got := maskEvidenceFor(".env", "VITE_SECRET_KEY="); got != "VITE_SECRET_KEY=" {
		t.Errorf("empty value: %q", got)
	}
}

// 한 줄에서 닫히지 않은 따옴표는 어디에 있든 줄 끝까지 가린다.
func TestUnclosedQuotesAnywhereMaskTheRest(t *testing.T) {
	words := "zoo quartz vessel amber robot tunnel"
	for _, q := range []string{`"`, `'`, "`"} {
		lines := []string{
			`VITE_SECRET=[` + q + words,
			`VITE_SECRET_KEY={` + q + `a` + q + `: ` + q + words,
			`const x = { VITE_SECRET_KEY: ` + q + words,
			`const VITE_SECRET_KEY = foo(` + q + words,
			`await w.signTransaction(req.body, ` + q + words,
			`foo(a, b, ` + q + words + ` , more`,
		}
		for _, l := range lines {
			got := maskEvidenceFor("src/a.ts", l)
			for _, w := range strings.Fields(words) {
				if strings.Contains(got, w) {
					t.Errorf("%q -> %q: %q printed", l, got, w)
					break
				}
			}
			if !strings.Contains(got, q+"****") {
				t.Errorf("%q -> %q: no masked rest", l, got)
			}
		}
	}
	// 닫힌 따옴표는 이전과 같다.
	if got := maskEvidenceFor("src/a.ts", `API_TOKEN = "hunter2"`); got != `API_TOKEN = "****"` {
		t.Errorf("closed quote changed: %q", got)
	}
}

// 비교용: 구분 문자가 다른 단어 나열이 주석에 있어도 나오지 않는다.
func TestSeparatorShapesInCommentsAreNotPrinted(t *testing.T) {
	words := append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
		"glide", "pencil", "north", "spring", "cabin", "onion")
	join := func(ws []string, sep string) string { return strings.Join(ws, sep) }
	var num1, num2 []string
	for i, w := range words {
		num1 = append(num1, string(rune('1'+i%9))+" "+w)
		num2 = append(num2, string(rune('1'+i%9))+":"+w)
	}
	seqs := map[string]string{
		"dash":      join(words, " - "),
		"pipe":      join(words, "|"),
		"semicolon": join(words, ";"),
		"slash":     join(words, " / "),
		"emoji":     join(words, " 🙂 "),
		"num space": join(num1, " "),
		"num colon": join(num2, " "),
		"ten words": join(words[:10], " "),
		"hex split": r3HexGroups("r3-hex-split", 16),
	}
	for name, seq := range seqs {
		for _, rel := range []string{"src/a.ts", ".env", "a.py", "a.yaml"} {
			marker := "// "
			if rel != "src/a.ts" {
				marker = "# "
			}
			line := "VITE_PRIVATE_KEY=abcdefgh " + marker + seq
			if rel == "src/a.ts" {
				line = "const k = import.meta.env.VITE_PRIVATE_KEY; " + marker + seq
			}
			got := maskEvidenceFor(rel, line)
			for _, w := range append(words, "a1b2", "c3d4", "e5f6") {
				if strings.Contains(got, w) {
					t.Errorf("%s %s: %q printed in %q", name, rel, w, got)
					break
				}
			}
		}
	}
}

// 이스케이프된 따옴표가 아주 많은 줄도 줄 길이에 비례해서 처리한다.
// maskStallLimit은 멈춘 것처럼 보이는 경우만 잡는 상한이다.
func TestMaskGeneralHandlesEscapedQuotesInLinearTime(t *testing.T) {
	line := strings.Repeat(`\"`, 200000)
	start := time.Now()
	_ = maskGeneral(line)
	_ = maskEvidenceFor("src/a.ts", "x = "+line)
	if d := time.Since(start); d > maskStallLimit {
		t.Errorf("%d bytes took %v", len(line), d)
	}
}

func TestMaskEvidenceKeepsOneSharedPath(t *testing.T) {
	// 파일 종류를 모르는 maskEvidence도 같은 규칙을 따른다.
	if got := maskEvidence("a = 1 // zoo"); !strings.Contains(got, commentMarker) || strings.Contains(got, "zoo") {
		t.Errorf("%q", got)
	}
}
