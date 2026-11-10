package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 구분 문자가 다른 단어 나열, 10단어 구문, 공백으로 나눈 16진수, 닫히지 않은 따옴표를
// adk scan으로 돌려 md, json, sarif와 표준 출력에 단어와 키 조각이 없는지 본다.
// 값은 시험 안에서 조립하고 임시 폴더의 시험용 저장소에만 쓴다.
func TestFailClosedEvidenceThroughScan(t *testing.T) {
	useFakeDeps(t)
	words := append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
		"glide", "pencil", "north", "spring", "cabin", "onion")
	var num1, num2 []string
	for i, w := range words {
		num1 = append(num1, string(rune('1'+i%9))+" "+w)
		num2 = append(num2, string(rune('1'+i%9))+":"+w)
	}
	sum := sha256.Sum256([]byte("cli-canary-r3"))
	raw := hex.EncodeToString(sum[:])
	key := "0x" + raw
	var groups []string
	for i := 0; i+4 <= len(raw); i += 4 {
		groups = append(groups, raw[i:i+4])
	}
	seqs := []string{
		strings.Join(words, " - "),
		strings.Join(words, "|"),
		strings.Join(words, ";"),
		strings.Join(words, " / "),
		strings.Join(words, " 🙂 "),
		strings.Join(num1, " "),
		strings.Join(num2, " "),
		strings.Join(words[:10], " "),
		strings.Join(groups, " "),
	}

	var env, ts []string
	for _, s := range seqs {
		env = append(env, "VITE_PRIVATE_KEY=abcdefgh # "+s, "VITE_SECRET_KEY="+s)
		ts = append(ts, "const k = import.meta.env.VITE_PRIVATE_KEY; // "+s, "const k = import.meta.env.VITE_SECRET_KEY; /* "+s)
	}
	few := strings.Join(words[:6], " ")
	var unclosed []string
	for _, q := range []string{`"`, `'`, "`"} {
		unclosed = append(unclosed,
			`const a = [{ VITE_SECRET: [`+q+few,
			`const b = { VITE_SECRET_KEY: `+q+few,
			`const VITE_SECRET_KEY = foo(`+q+few,
			`const c = {`+q+`a`+q+`: `+q+`VITE_SECRET_KEY`+q+`, v: [`+q+few,
			`await w.signTransaction(req.body, `+q+few)
	}
	ts = append(ts, unclosed...)

	app := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies":{"react":"19.0.0","ethers":"6.0.0"}}`,
		".env":         strings.Join(env, "\n") + "\n",
		"src/a.ts":     strings.Join(ts, "\n") + "\n",
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
	code, so, se := runCLI(t, "scan", app, "--format", "md,json,sarif", "--out", out, "--offline")
	if code == 2 {
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
	if n := len(regexp.MustCompile(`"id": "RE-001"`).FindAllString(js, -1)); n < len(env)+len(seqs)*2+len(unclosed)-6 {
		t.Errorf("RE-001 findings = %d, a line may have been dropped", n)
	}
	if !strings.Contains(js, "(주석 생략)") {
		t.Error("evidence never says a comment was left out")
	}
	longHex := regexp.MustCompile(`[0-9a-f]{16,}`)
	for name, text := range texts {
		for _, w := range words {
			if strings.Contains(text, w) {
				t.Errorf("%s: word %q printed", name, w)
			}
		}
		clean := longHex.ReplaceAllString(scrubTempPaths(text, filepath.Dir(app), filepath.Dir(out)), "")
		for _, g := range groups {
			if strings.Contains(clean, g) {
				t.Errorf("%s: 4-char piece %q of the key printed", name, g)
			}
		}
		if strings.Contains(text, raw) {
			t.Errorf("%s: full key", name)
		}
	}
	_ = key
}
