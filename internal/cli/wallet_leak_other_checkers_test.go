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

// 다른 검사기(autorun의 tasks.json·package.json, cicd의 uses, supabase의 테이블 이름)와
// .env* 이름 자리, %20·&nbsp; 이스케이프, 200글자 경계를 넘는 키를 adk scan으로 돌려
// 표준 출력, 표준 오류, 모든 출력 파일과 증적 파일에 구문의 단어와 키의 4글자 조각이 없는지 본다.
// 값은 시험 안에서 조립하고 임시 폴더의 시험용 저장소에만 쓴다.

var r5Words = append([]string{"zoo", "quartz", "vessel", "amber", "lemur", "tunnel"},
	"glide", "pencil", "walnut", "bison", "cobalt", "oyster")

// r5Key는 숫자와 a~f가 번갈아 나오는 64자리 16진수다(4글자 조각이 다른 출력과 우연히 겹치지 않게).
func r5Key(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	var b strings.Builder
	for _, c := range sum {
		b.WriteByte('0' + c%10)
		b.WriteByte('a' + (c>>4)%6)
	}
	return b.String()
}

func r5Groups(key string) []string {
	var g []string
	for i := 0; i+4 <= len(key); i += 4 {
		g = append(g, key[i:i+4])
	}
	return g
}

type r5Finding struct{ ID, Location, Evidence, Title, Fingerprint string }

// r5Repo는 시험용 저장소를 만들어 adk scan을 돌리고, 출력 글자 모음과 결과 목록을 돌려준다.
func r5Repo(t *testing.T, words []string, key string) (map[string]string, []r5Finding) {
	t.Helper()
	phrase := strings.Join(words, " ")
	upper := strings.ToUpper(strings.Join(words, "_"))
	quoted, _ := json.Marshal(words)
	tasks := `{"version":"2.0.0","tasks":[` +
		`{"label":"a","type":"shell","command":"echo ` + phrase + ` ` + key + `","runOptions":{"runOn":"folderOpen"}},` +
		`{"label":"b","type":"process","command":"run","args":` + string(quoted) + `,"runOptions":{"runOn":"folderOpen"}},` +
		`{"label":"` + strings.Join(words, "-") + `","type":"shell","command":"x","runOptions":{"runOn":"folderOpen"}}]}`
	pkg := `{"dependencies":{"react":"19.0.0"},"scripts":{"postinstall":"node -e ` + phrase + `","preinstall":"echo ` + key + `","prepare":"echo ` + strings.Join(r5Groups(key), "/") + `"}}`
	wf := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: " + words[0] + "/" + strings.Join(words[1:], "-") + "@main\n" +
		"      - uses: " + strings.Join(words[:6], "-") + "/" + strings.Join(words[6:], "-") + "@v1\n"
	sql := "create table public." + strings.ToLower(upper) + " (id int);\n"
	pad := strings.Repeat("x", 150)
	files := map[string]string{
		"package.json":                 pkg,
		".vscode/tasks.json":           tasks,
		".github/workflows/ci.yml":     wf,
		"supabase/migrations/0001.sql": sql,
		".envrc":                       strings.Join(words[:6], "-") + "=x\nexport " + strings.Join(words[6:], ".") + "=y\nexport VITE_SECRET_KEY=1\n",
		"src/a.ts": "const k = import.meta.env.VITE_SECRET_KEY; x = " + strings.Join(words, "%20") + ";\n" +
			"const k = import.meta.env.VITE_SECRET_KEY; x = " + strings.Join(words, "&nbsp;") + ";\n" +
			"const k = import.meta.env.VITE_SECRET_KEY; const p = \"" + pad + "/" + strings.Join(r5Groups(key), "/") + "\";\n",
		"index.html": `<script src="https://cdn.example.test/a.js"></script> <p>` + strings.Join(words, "&#160;") + "</p>\n",
	}
	app := t.TempDir()
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
	for name, text := range texts {
		// The temp folders' random names can match a short piece of the key.
		texts[name] = scrubTempPaths(text, filepath.Dir(app), filepath.Dir(out))
	}
	for _, name := range []string{"adk-report.md", "adk-report.json", "adk-report.sarif", "adk-evidence.json"} {
		if _, ok := texts[name]; !ok {
			t.Fatalf("missing output %s", name)
		}
	}
	var rep struct{ Findings []r5Finding }
	if err := json.Unmarshal([]byte(texts["adk-report.json"]), &rep); err != nil {
		t.Fatal(err)
	}
	return texts, rep.Findings
}

func TestOtherCheckersNeverPrintKeyMaterial(t *testing.T) {
	useFakeDeps(t)
	key := r5Key("cli-canary-r5")
	texts, fs := r5Repo(t, r5Words, key)

	// 결과가 실제로 나와야 시험이 뜻이 있다.
	count := map[string]int{}
	for _, f := range fs {
		count[f.ID]++
	}
	for id, min := range map[string]int{"AR-001": 3, "AR-005": 3, "CI-002": 2, "SB-001": 1, "RE-001": 4, "WEB-001": 1} {
		if count[id] < min {
			t.Errorf("%s findings = %d, want at least %d", id, count[id], min)
		}
	}

	longHex := regexp.MustCompile(`[0-9a-f]{16,}`)
	for name, text := range texts {
		low := strings.ToLower(text)
		for _, w := range r5Words {
			if strings.Contains(low, w) {
				t.Errorf("%s: word %q printed", name, w)
			}
		}
		clean := longHex.ReplaceAllString(low, "")
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(clean, key[i:i+4]) {
				t.Errorf("%s: 4-char piece %q of the key printed", name, key[i:i+4])
			}
		}
	}

	// 구조 정보로 지문을 만드는 검사기(CI-002, SB-001)는 키나 구문의 마지막만 달라도 지문이 달라진다.
	// 자동 실행 설정(AR-*)의 지문은 보이는 근거에서 만들고 값을 쓰지 않으므로, 값의 끝이 달라도 같다.
	words2 := append(append([]string{}, r5Words[:11]...), "walrus")
	key2 := key[:60] + "9e9e"
	if key2 == key {
		key2 = key[:60] + "8d8d"
	}
	_, fs2 := r5Repo(t, words2, key2)
	fps := map[string]bool{}
	for _, f := range fs {
		fps[f.ID+"\x00"+f.Fingerprint] = true
	}
	for _, f := range fs2 {
		switch f.ID {
		case "CI-002", "SB-001":
			if fps[f.ID+"\x00"+f.Fingerprint] {
				t.Errorf("%s at %s: fingerprint did not change with the end of the value", f.ID, f.Location)
			}
		case "AR-001", "AR-005":
			if !fps[f.ID+"\x00"+f.Fingerprint] {
				t.Errorf("%s at %s: fingerprint depends on the end of the value (evidence %q)", f.ID, f.Location, f.Evidence)
			}
		}
	}
}
