package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 단어 나열과 키가 여러 모양으로 다른 규칙의 줄에 나와도 어느 출력에도 남지 않는지 본다.
// 값은 시험 안에서 조립하고 임시 폴더의 시험용 저장소에만 쓴다.
func TestSeedShapesNeverReachAnyOutput(t *testing.T) {
	useFakeDeps(t)
	base := append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
		"glide", "pencil", "north", "spring", "cabin", "onion")
	korean := []string{"곰팡이", "두꺼비", "라일락", "멸치", "붕어빵", "솔방울", "옹기", "짜장", "칡뿌리", "팥죽", "해바라기", "호박엿"}
	type shape struct {
		name   string
		tokens []string
		text   string
	}
	var shapes []shape
	add := func(name string, words []string, sep string) {
		shapes = append(shapes, shape{name, words, strings.Join(words, sep)})
	}
	var up, ti, num, par []string
	for i, w := range base {
		up = append(up, strings.ToUpper(w))
		ti = append(ti, strings.ToUpper(w[:1])+w[1:])
		num = append(num, string(rune('1'+i%9))+"."+w)
		par = append(par, string(rune('1'+i%9))+") "+w)
	}
	add("lower", base, " ")
	add("upper", up, " ")
	add("title", ti, " ")
	add("tabs", base, "\t")
	add("nbsp", base, " ")
	add("commas", base, ",")
	add("comma space", base, ", ")
	add("eleven", base[:11], " ")
	shapes = append(shapes, shape{"numbered dot", base, strings.Join(num, " ")}, shape{"numbered paren", base, strings.Join(par, " ")})
	add("korean", korean, " ")

	sum := sha256.Sum256([]byte("cli-canary-r2b"))
	raw := hex.EncodeToString(sum[:])
	key := "0x" + raw

	var env []string
	var code []string
	var words []string
	for _, sh := range shapes {
		env = append(env,
			"VITE_PRIVATE_KEY=abcdefgh # "+sh.text,
			`VITE_SECRET_KEY="`+sh.text+`"`,
			"VITE_SECRET_KEY="+sh.text,
			"VITE_API_SECRET='"+sh.text+"' // "+sh.text,
		)
		code = append(code, "await w.signTransaction(req.body); // "+sh.text)
		// 주석 밖의 구문: 이 줄의 근거에는 가림 안내가 나와야 한다(아래 근거 검사).
		code = append(code, "await w.signTransaction(req.body, "+sh.text+");")
		words = append(words, sh.tokens...)
	}
	// 두 줄에 걸친 값: 첫 줄의 여섯 단어가 그대로 나오면 안 된다.
	env = append(env, `VITE_SECRET="`+strings.Join(base[:6], " "), strings.Join(base[6:], " ")+`"`)
	// 같은 모양의 키가 든 줄 둘은 둘 다 보고되어야 한다.
	key2 := "0x" + hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("cli-canary-three")); return s[:] }())
	env = append(env, "VITE_PRIVATE_KEY="+key, "VITE_PRIVATE_KEY="+key2)
	code = append(code, `await w.signTransaction(req.body, new Wallet("`+key+`"));`, `await w.signTransaction(req.body, new Wallet("`+key2+`"));`)

	app := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies":{"react":"19.0.0","ethers":"6.0.0"}}`,
		".env":         strings.Join(env, "\n") + "\n",
		"src/a.ts":     strings.Join(code, "\n") + "\n",
	}
	for name, body := range files {
		p := filepath.Join(app, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	code2, so, se := runCLI(t, "scan", app, "--format", "md,json,sarif", "--out", out, "--offline")
	if code2 == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	texts := map[string]string{"stdout": so, "stderr": se}
	ents, err := os.ReadDir(out)
	if err != nil || len(ents) < 4 {
		t.Fatalf("outputs: %v %v", ents, err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		texts[e.Name()] = string(b)
	}
	js := texts["adk-report.json"]
	// 같은 키 모양의 줄 두 개: 두 줄 모두 RE-001, 코드 쪽 두 줄 모두 WL-002.
	if n := len(regexp.MustCompile(`"id": "RE-001"`).FindAllString(js, -1)); n < len(shapes)*4+3 {
		t.Errorf("RE-001 findings = %d, want at least %d (a line was merged away)", n, len(shapes)*4+3)
	}
	// WL-002 줄: 모양마다 주석 달린 줄과 주석 밖 구문 줄 하나씩, 그리고 키 줄 둘.
	if n := len(regexp.MustCompile(`"id": "WL-002"`).FindAllString(js, -1)); n < 2*len(shapes)+2 {
		t.Errorf("WL-002 findings = %d, want at least %d (a line was merged away)", n, 2*len(shapes)+2)
	}
	// 가림 안내는 설명 글(explain_ko)에도 있으므로 JSON 전체가 아니라 근거 필드에서 찾는다.
	var rep struct {
		Findings []struct{ ID, Location, Evidence string }
	}
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatal(err)
	}
	marked := 0
	for _, f := range rep.Findings {
		ev := strings.ToLower(f.Evidence)
		for _, w := range words {
			if strings.Contains(ev, strings.ToLower(w)) {
				t.Errorf("%s at %s: evidence shows word %q: %q", f.ID, f.Location, w, f.Evidence)
				break
			}
		}
		if f.Location == "src/a.ts" && strings.Contains(f.Evidence, "(긴 단어 나열을 가림)") {
			marked++
		}
	}
	if marked < len(shapes) {
		t.Errorf("evidence of src/a.ts says a word list was hidden %d times, want at least %d (one per phrase line)", marked, len(shapes))
	}
	longHex := regexp.MustCompile(`[0-9a-f]{16,}`)
	for name, text := range texts {
		for _, w := range words {
			if strings.Contains(text, w) {
				t.Errorf("%s: word %q printed", name, w)
			}
		}
		if strings.Contains(text, raw) {
			t.Errorf("%s: full key", name)
		}
		clean := longHex.ReplaceAllString(scrubTempPaths(text, filepath.Dir(app), filepath.Dir(out)), "")
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(clean, key[i:i+4]) {
				at := strings.Index(clean, key[i:i+4])
				t.Errorf("%s: 4-char piece %q of the key: ...%s...", name, key[i:i+4], clean[max(0, at-60):min(len(clean), at+60)])
			}
		}
	}
}
