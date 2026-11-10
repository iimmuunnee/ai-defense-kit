package rules

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 값은 모두 시험 안에서 조립한다. 파일로 저장하지 않는다.

var r4Words = append([]string{"zoo", "quartz", "vessel", "amber", "lemur", "tunnel"},
	"glide", "pencil", "walnut", "bison", "cobalt", "oyster")

// r4Key는 해시에서 만든 64자리 16진수다. 숫자와 영문자가 번갈아 나오므로
// 어느 4글자 조각도 숫자만이거나 영문자만이 아니어서 출력의 다른 글자와 우연히 겹치지 않는다.
func r4Key(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	var b strings.Builder
	for _, c := range sum {
		b.WriteByte('0' + c%10)
		b.WriteByte('a' + (c>>4)%6)
	}
	return b.String()
}

func r4Groups(key string) []string {
	var g []string
	for i := 0; i+4 <= len(key); i += 4 {
		g = append(g, key[i:i+4])
	}
	return g
}

// r4Leaks는 text에 남은 단어(대소문자 무시)와 키의 4글자 조각을 모은다.
func r4Leaks(text string, words []string, key string) []string {
	var out []string
	low := strings.ToLower(text)
	for _, w := range words {
		if strings.Contains(low, strings.ToLower(w)) {
			out = append(out, "word "+w)
		}
	}
	if key != "" {
		clean := longHex.ReplaceAllString(low, "")
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(clean, key[i:i+4]) {
				out = append(out, "4-char piece "+key[i:i+4])
			}
		}
	}
	return out
}

// A. .env* 규칙이 보는 파일(.envrc, .env-local, .env_local 등)은 모두 환경 파일이다.
// 값은 모양과 상관없이 보이지 않고, = 이 없는 줄은 주석 표시만 남기고 모두 가린다.
func TestEnvStarFilesHideEverything(t *testing.T) {
	six := r4Words[:6]
	files := []string{".env", ".env.production", ".envrc", ".env-local", ".env_local", "prod.env", "config/.envrc", "apps/web/.env-staging"}
	for _, rel := range files {
		if !isEnvFile(rel) {
			t.Errorf("%s is not an env file", rel)
		}
		lines := map[string]string{
			"export VITE_SECRET_KEY=" + strings.Join(six, ";"):    "export VITE_SECRET_KEY=****",
			"VITE_SECRET_KEY=" + strings.Join(six, "|"):           "VITE_SECRET_KEY=****",
			"VITE_SECRET_KEY " + strings.Join(six, " "):           "****",
			strings.Join(six, " ") + `"`:                          "****",
			`"VITE_SECRET_KEY": "` + strings.Join(six, " ") + `"`: "****",
			"  # " + strings.Join(six, " "):                       commentMarker,
			"#" + strings.Join(six, ";"):                          commentMarker,
		}
		for line, want := range lines {
			got := maskEvidenceFor(rel, line)
			if l := r4Leaks(got, six, ""); len(l) > 0 {
				t.Errorf("%s %q -> %q: leaked %v", rel, line, got, l)
			}
			if got != want {
				t.Errorf("%s %q -> %q, want %q", rel, line, got, want)
			}
		}
	}
	for _, rel := range []string{"src/env.ts", "envoy.yaml", "src/environment.go"} {
		if isEnvFile(rel) {
			t.Errorf("%s taken for an env file", rel)
		}
	}
	// 규칙을 거친 근거도 같다.
	for _, rel := range []string{".envrc", ".env-local", ".env_local"} {
		got := scanText(t, "RE-001", rel, "export VITE_SECRET_KEY="+strings.Join(six, ";")+"\n", []string{"react"})
		if len(got) != 1 {
			t.Fatalf("%s: findings = %d", rel, len(got))
		}
		if l := r4Leaks(got[0].Evidence, six, ""); len(l) > 0 || got[0].Evidence != "export VITE_SECRET_KEY=****" {
			t.Errorf("%s: evidence %q leaked %v", rel, got[0].Evidence, l)
		}
	}
}

// B. 주석은 따옴표 짝과 상관없이 자른다.
func TestCommentCutIgnoresQuotes(t *testing.T) {
	six := strings.Join(r4Words[:6], " ")
	cases := []struct{ rel, line, keep string }{
		{"src/a.ts", `const s = x.replace(/'/g, ""); // don't: ` + six, "const s ="},
		{"src/a.ts", `const s = x.replace(/"/g, ''); /* it"s ` + six, "const s ="},
		{"src/a.ts", "const X =//" + six, "const X ="},
		{"src/a.ts", "switch (v) { case 1://" + six, "switch (v)"},
		{"src/a.ts", "const o = { K://" + six, "const o ="},
		{"src/a.ts", `const s = "x // ` + six + `";`, "const s ="},
		{"src/a.ts", `const s = "it's"; // ` + six, "const s ="},
		{"src/a.go", "x := `a` // it's " + six, "x :="},
		{"a.vue", `<a :x="'b'">{{ y }}</a> // don't ` + six, "<a"},
		{"a.py", `s = "a # ` + six + `"`, "s ="},
		{"a.py", `s = "it's" # ` + six, "s ="},
		{"a.php", `echo "it's"; # ` + six, "echo"},
		{"a.yaml", `k: "it's" # ` + six, "k:"},
		{"a.yml", `k: 'it''s' # ` + six, "k:"},
		{"a.sql", `select '--' -- ` + six, "select"},
		{"a.html", `<p title="<!--">x</p> <!-- ` + six, "<p"},
		{"a.unknown", `a = "it's" // ` + six, "a ="},
	}
	for _, c := range cases {
		got := maskEvidenceFor(c.rel, c.line)
		if l := r4Leaks(got, r4Words[:6], ""); len(l) > 0 {
			t.Errorf("%s %q -> %q: leaked %v", c.rel, c.line, got, l)
		}
		if !strings.Contains(got, commentMarker) {
			t.Errorf("%s %q -> %q: no marker", c.rel, c.line, got)
		}
		if !strings.HasPrefix(got, c.keep) {
			t.Errorf("%s %q -> %q: lost %q", c.rel, c.line, got, c.keep)
		}
	}
	// URL의 // 는 주석이 아니다.
	for _, c := range []struct{ rel, line, want string }{
		{"src/a.ts", `const u = "https://example.test/a"; fetch(u);`, `const u = "https://example.test/a"; fetch(u);`},
		{"src/a.ts", `fetch("http://example.test/api/v1/users");`, `fetch("http://example.test/api/v1/users");`},
		{"src/a.ts", `open("file:///tmp/x");`, `open("file:///tmp/x");`},
		{"a.html", `<script src="https://cdn.example.test/a.js"></script>`, `<script src="https://cdn.example.test/a.js"></script>`},
	} {
		if got := maskEvidenceFor(c.rel, c.line); got != c.want {
			t.Errorf("%s %q -> %q, want %q", c.rel, c.line, got, c.want)
		}
	}
}

// C. 키와 구문 모양은 경로, 상대 경로, URL 경로, 모듈 이름, UPPER_SNAKE, 점으로 이은 키,
// | 로 나눈 모양이어도 어디서나 가린다.
func TestWideShapesAreHiddenAnywhere(t *testing.T) {
	w := r4Words
	up := make([]string, len(w))
	for i, s := range w {
		up[i] = strings.ToUpper(s)
	}
	key := r4Key("wide-unit")
	g := r4Groups(key)
	shapes := map[string]string{
		"path":          `"/` + strings.Join(w, "/") + `"`,
		"relative":      `"./` + strings.Join(w, "/") + `"`,
		"parent":        `"../` + strings.Join(w, "/") + `"`,
		"url path":      `"https://x.test/` + strings.Join(w, "/") + `"`,
		"url query":     `"https://x.test/?q=` + strings.Join(w, "+") + `"`,
		"module":        `"@` + w[0] + "/" + strings.Join(w[1:], "-") + `"`,
		"upper snake":   `"` + strings.Join(up, "_") + `"`,
		"pipes":         `"` + strings.Join(w, "|") + `"`,
		"dotted key":    `{"` + strings.Join(w, ".") + `": 1}`,
		"dotted code":   strings.Join(w, ".") + ";",
		"snake code":    strings.Join(up, "_") + ";",
		"colons":        `"` + strings.Join(w, ":") + `"`,
		"semicolons":    strings.Join(w, ";") + ";",
		"korean":        `"/` + strings.Join([]string{"곰팡이", "두꺼비", "라일락", "멸치", "붕어빵", "솔방울", "옹기", "짜장", "칡뿌리", "팥죽", "해바라기"}, "/") + `/" + v2`,
		"numbered":      `"1.` + strings.Join(w, " 2.") + `"`,
		"hex slash":     `"/` + strings.Join(g, "/") + `"`,
		"hex dash":      `"` + strings.Join(g, "-") + `"`,
		"hex colon":     strings.Join(g, ":") + ";",
		"hex dotted":    `{"` + strings.Join(g, ".") + `": 1}`,
		"hex 0x groups": `"0x` + strings.Join(g, "_") + `"`,
	}
	for name, s := range shapes {
		for _, line := range []string{
			"const p = " + s,
			"x = " + s,
			"const k = import.meta.env.VITE_SECRET_KEY; const p = " + s,
		} {
			got := maskEvidenceFor("src/a.ts", line)
			if l := r4Leaks(got, w, key); len(l) > 0 {
				t.Errorf("%s: %q -> %q: leaked %v", name, line, got, l)
			}
		}
		// 규칙을 거친 근거에도 없다.
		line := "const k = import.meta.env.VITE_SECRET_KEY; const p = " + s
		got := scanText(t, "RE-001", "src/a.ts", line+"\n", []string{"react"})
		if len(got) != 1 {
			t.Fatalf("%s: findings = %d", name, len(got))
		}
		if l := r4Leaks(got[0].Evidence, w, key); len(l) > 0 {
			t.Errorf("%s: evidence %q leaked %v", name, got[0].Evidence, l)
		}
		// 지문은 줄 전체의 해시가 아니라 가린 근거와 순번에서 만든다.
		if got[0].Fingerprint == finding.MakeFingerprint("RE-001", "src/a.ts", line) {
			t.Errorf("%s: fingerprint is a hash of the whole line", name)
		}
	}
	// 숫자 목록도 자릿수를 더해 64자리 이상이면 가린다(바이트 배열로 적은 키).
	var nums []string
	for _, c := range sha256.Sum256([]byte("wide-bytes")) {
		nums = append(nums, strconv.Itoa(int(c)))
	}
	line := "const b = new Uint8Array([" + strings.Join(nums, ", ") + "]);"
	got := maskEvidenceFor("src/a.ts", line)
	if !strings.Contains(got, "(64자리 이상 16진수를 가림)") || strings.Contains(got, nums[3]+", "+nums[4]) {
		t.Errorf("byte list %q -> %q", line, got)
	}
	// 한글 단어 나열 뒤의 다른 코드(나열을 끊는 v2)는 그대로다.
	if got := maskEvidenceFor("src/a.ts", "x = "+shapes["korean"]); strings.Contains(got, "두꺼비") || !strings.Contains(got, "+ v2") {
		t.Errorf("korean path -> %q", got)
	}
}

// 줄 전체에서 짧은 단어가 11개 미만으로 이어지는 경로와 보통 코드는 이전과 같다.
// (fetch, read도 한 단어로 센다.)
func TestShortPathsAndCodeUnchanged(t *testing.T) {
	ten := r4Words[:9]
	for _, line := range []string{
		`fetch("/` + strings.Join(ten, "/") + `");`,
		`fetch("./` + strings.Join(ten, "/") + `");`,
		`read("` + strings.ToUpper(strings.Join(ten, "_")) + `");`,
		`fetch("/api/v1/users/profile/settings");`,
		`import x from "@scope/pkg/sub";`,
		`read("NEXT_PUBLIC_SUPABASE_URL");`,
		`const k = import.meta.env.VITE_SECRET_KEY;`,
		`fetch("https://example.test/a/b/c");`,
		`const total = items.map((x) => x.price * x.qty).reduce((a, b) => a + b, 0);`,
	} {
		if got := maskEvidenceFor("src/a.ts", line); got != line {
			t.Errorf("%q -> %q", line, got)
		}
	}
}

// 넓힌 토큰 나누기도 줄 길이에 비례한다.
func TestWideScanIsLinear(t *testing.T) {
	line := strings.Repeat("ab/0a/c1d2/", 100000) + strings.Repeat("zz-", 100000)
	start := time.Now()
	_ = finding.ScrubKeyMaterial(line)
	_ = maskEvidenceFor("src/a.ts", "x = "+line)
	if d := time.Since(start); d > maskStallLimit {
		t.Errorf("%d bytes took %v", len(line), d)
	}
}
