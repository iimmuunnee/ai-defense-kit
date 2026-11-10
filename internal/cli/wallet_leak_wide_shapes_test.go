package cli

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// .env* 파일, 따옴표와 상관없는 주석, 경로·모듈·UPPER_SNAKE·점·| 모양의 구문과 키를
// adk scan(md, json, sarif)으로 돌려 표준 출력, 표준 오류, 모든 출력 파일과 증적 파일에
// 구문의 어느 단어도, 키의 어느 4글자 조각도 없는지 본다.
// 값은 시험 안에서 조립하고 임시 폴더의 시험용 저장소에만 쓴다.
func TestWideShapesNeverReachAnyOutput(t *testing.T) {
	useFakeDeps(t)
	words := append([]string{"zoo", "quartz", "vessel", "amber", "lemur", "tunnel"},
		"glide", "pencil", "walnut", "bison", "cobalt", "oyster")
	up := make([]string, len(words))
	for i, w := range words {
		up[i] = strings.ToUpper(w)
	}
	// 숫자와 영문자가 번갈아 나오는 64자리 16진수: 어느 4글자 조각도 다른 출력 글자와 우연히 겹치지 않는다.
	sum := sha256.Sum256([]byte("cli-canary-r4"))
	var kb strings.Builder
	for _, c := range sum {
		kb.WriteByte('0' + c%10)
		kb.WriteByte('a' + (c>>4)%6)
	}
	key := kb.String()
	var groups []string
	for i := 0; i+4 <= len(key); i += 4 {
		groups = append(groups, key[i:i+4])
	}
	six := strings.Join(words[:6], " ")

	// A: .env* 규칙이 보는 파일들
	envLines := []string{
		"export VITE_SECRET_KEY=" + strings.Join(words, ";"),
		"export VITE_SECRET_KEY=" + strings.Join(words[:6], ";"),
		"VITE_SECRET_KEY " + six,
		`VITE_PRIVATE_KEY="` + six,
		strings.Join(words[6:], " ") + `"`,
		"VITE_PRIVATE_KEY=0x" + key,
		"# " + six,
	}
	envFiles := []string{".envrc", ".env-local", ".env_local", "prod.env"}

	// B: 따옴표와 상관없이 주석을 자른다
	pre := "const k = import.meta.env.VITE_SECRET_KEY; "
	ts := []string{
		pre + `const s = x.replace(/'/g, ""); // don't: ` + six,
		pre + "const X =//" + six,
		pre + "switch (v) { case 1://" + six,
		pre + `const s = "x // ` + six + `";`,
	}
	// C: 닫힌 문자열과 따옴표 밖 코드의 넓은 모양
	shapes := []string{
		`"/` + strings.Join(words, "/") + `"`,
		`"./` + strings.Join(words, "/") + `"`,
		`"https://x.test/` + strings.Join(words, "/") + `"`,
		`"@` + words[0] + "/" + strings.Join(words[1:], "-") + `"`,
		`"` + strings.Join(up, "_") + `"`,
		`{"` + strings.Join(words, ".") + `": 1}`,
		strings.Join(words, ".") + ";",
		`"` + strings.Join(words, "|") + `"`,
		`"/` + strings.Join(groups, "/") + `"`,
		strings.Join(groups, ":") + ";",
	}
	for _, s := range shapes {
		ts = append(ts, pre+"const p = "+s, pre+"x = "+s)
	}

	app := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies":{"react":"19.0.0","ethers":"6.0.0"}}`,
		"src/a.ts":     strings.Join(ts, "\n") + "\n",
	}
	for _, f := range envFiles {
		files[f] = strings.Join(envLines, "\n") + "\n"
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
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		texts[e.Name()] = string(b)
	}
	for _, name := range []string{"adk-report.md", "adk-report.json", "adk-report.sarif", "adk-evidence.json"} {
		if _, ok := texts[name]; !ok {
			t.Fatalf("missing output %s", name)
		}
	}

	// 줄마다 결과가 나와야 시험이 뜻이 있다.
	var rep struct {
		Findings []struct{ ID, Location, Evidence string }
	}
	if err := json.Unmarshal([]byte(texts["adk-report.json"]), &rep); err != nil {
		t.Fatal(err)
	}
	perFile := map[string]int{}
	for _, f := range rep.Findings {
		if f.ID == "RE-001" {
			perFile[f.Location]++
		}
	}
	if perFile["src/a.ts"] != len(ts) {
		t.Errorf("RE-001 in src/a.ts = %d, want %d", perFile["src/a.ts"], len(ts))
	}
	for _, f := range envFiles[:3] { // prod.env는 .env* 규칙 대상이 아니고 비밀 키 검사만 본다.
		if perFile[f] < 4 {
			t.Errorf("RE-001 in %s = %d, want at least 4", f, perFile[f])
		}
	}

	longHex := regexp.MustCompile(`[0-9a-f]{16,}`)
	for name, text := range texts {
		low := strings.ToLower(scrubTempPaths(text, filepath.Dir(app), filepath.Dir(out)))
		for _, w := range words {
			if strings.Contains(low, w) {
				t.Errorf("%s: word %q printed", name, w)
			}
		}
		if strings.Contains(low, key) {
			t.Errorf("%s: full key printed", name)
		}
		clean := longHex.ReplaceAllString(low, "")
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(clean, key[i:i+4]) {
				t.Errorf("%s: 4-char piece %q of the key printed", name, key[i:i+4])
			}
		}
	}
}
