package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// B1: 자동 실행 설정에서 따로 보이는 값(tasks.json의 label, 객체 키, 인자 하나, 한 단어씩
// 나눈 인자 배열, command, package.json 스크립트)은 값 규칙으로 가린다. UPPER_SNAKE, 한글
// 단어를 _로 이은 것, 섞인 구분 문자로 이은 12단어 구문이 adk scan의 어느 출력에도 4단어
// 이상 이어서 나오지 않아야 한다. 구문은 시험 안에서 조립하고 임시 폴더에만 쓴다.

// 단어 목록은 한 줄에 여섯 개씩만 적는다(파일에 구문 모양의 줄이 생기지 않게).
var avlBase = append([]string{"zoo", "quartz", "vessel", "amber", "lemur", "tunnel"},
	"glide", "pencil", "walnut", "bison", "cobalt", "oyster")

var avlKorean = append([]string{"곰팡이", "두꺼비", "라일락", "멸치", "붕어빵", "솔방울"},
	"옹기", "짜장", "칡뿌리", "팥죽", "해바라기", "호박엿")

// avlShape는 구문의 단어와, 단어 i 뒤에 붙는 구분 문자를 돌려주는 함수다.
type avlShape struct {
	words []string
	sep   func(i int) string
}

func avlShapes() map[string]avlShape {
	var upper []string
	for _, w := range avlBase {
		upper = append(upper, strings.ToUpper(w))
	}
	mixed := []string{"-", "_", "."}
	return map[string]avlShape{
		"upper snake":      {upper, func(int) string { return "_" }},
		"korean underbar":  {avlKorean, func(int) string { return "_" }},
		"mixed separators": {avlBase, func(i int) string { return mixed[i%len(mixed)] }},
	}
}

// pieces는 구문을 구분 문자 바로 뒤에서 나눈 조각이다(마지막 조각에는 구분 문자가 없다).
func (s avlShape) pieces() []string {
	out := make([]string, len(s.words))
	for i, w := range s.words {
		out[i] = w
		if i < len(s.words)-1 {
			out[i] += s.sep(i)
		}
	}
	return out
}

// leadPieces는 구문을 구분 문자 바로 앞에서 나눈 조각이다(첫 조각에는 구분 문자가 없다).
func (s avlShape) leadPieces() []string {
	out := make([]string, len(s.words))
	for i, w := range s.words {
		out[i] = w
		if i > 0 {
			out[i] = s.sep(i-1) + w
		}
	}
	return out
}

func (s avlShape) phrase() string { return strings.Join(s.pieces(), "") }

func avlJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// avlTokens는 글자와 숫자의 묶음을 소문자로 돌려준다.
func avlTokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r)
	})
}

// avlRun4는 text에 구문의 단어가 4개 이상 이어서 나오는 곳을 돌려준다(없으면 "").
func avlRun4(text string, words []string) string {
	grams := map[string]bool{}
	for i := 0; i+4 <= len(words); i++ {
		grams[strings.ToLower(strings.Join(words[i:i+4], "\x00"))] = true
	}
	toks := avlTokens(text)
	for i := 0; i+4 <= len(toks); i++ {
		if grams[strings.Join(toks[i:i+4], "\x00")] {
			return strings.Join(toks[i:i+4], " ")
		}
	}
	return ""
}

type avlFinding struct{ ID, Location, Evidence string }

// avlScan writes rel with body in a new repository, runs adk scan, and returns
// every output text (stdout, stderr, each output file) and the findings.
func avlScan(t *testing.T, rel, body string) (map[string]string, []avlFinding) {
	t.Helper()
	app := t.TempDir()
	p := filepath.Join(app, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
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
	for _, name := range []string{"adk-report.md", "adk-report.json", "adk-report.sarif"} {
		if _, ok := texts[name]; !ok {
			t.Fatalf("missing output %s", name)
		}
	}
	var rep struct{ Findings []avlFinding }
	if err := json.Unmarshal([]byte(texts["adk-report.json"]), &rep); err != nil {
		t.Fatal(err)
	}
	return texts, rep.Findings
}

const avlFolderOpen = `"runOptions":{"runOn":"folderOpen"}`

func avlSplitArgs(s avlShape) (string, string) {
	return ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"run","type":"process","command":"node","args":` + avlJSON(s.pieces()) + `,` + avlFolderOpen + `}]}`
}

func TestAutorunStandaloneValuesHideWideShapes(t *testing.T) {
	useFakeDeps(t)
	const fo = avlFolderOpen
	places := map[string]func(avlShape) (string, string){
		"label": func(s avlShape) (string, string) {
			return ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":` + avlJSON(s.phrase()) + `,"type":"shell","command":"echo hi",` + fo + `}]}`
		},
		"object key": func(s avlShape) (string, string) {
			return ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"run","type":"shell","command":"echo hi",` + avlJSON(s.phrase()) + `:"x",` + fo + `}]}`
		},
		"single arg": func(s avlShape) (string, string) {
			return ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"run","type":"process","command":"node","args":` + avlJSON([]string{s.phrase()}) + `,` + fo + `}]}`
		},
		"split args": avlSplitArgs,
		"mcp args": func(s avlShape) (string, string) {
			return ".mcp.json", `{"mcpServers":{"tool":{"command":"node","args":` + avlJSON(s.pieces()) + `}}}`
		},
		// 구분 문자를 조각 앞에 붙인 모양(["ZOO", "_QUARTZ", ...]).
		"split args lead": func(s avlShape) (string, string) {
			return ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"run","type":"process","command":"node","args":` + avlJSON(s.leadPieces()) + `,` + fo + `}]}`
		},
		"mcp args lead": func(s avlShape) (string, string) {
			return ".mcp.json", `{"mcpServers":{"tool":{"command":"npx","args":` + avlJSON(append([]string{"-y", "pkg"}, s.leadPieces()...)) + `}}}`
		},
		"command": func(s avlShape) (string, string) {
			return ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"run","type":"shell","command":` + avlJSON("echo "+s.phrase()) + `,` + fo + `}]}`
		},
		"package script": func(s avlShape) (string, string) {
			return "package.json", `{"dependencies":{"react":"19.0.0"},"scripts":{"postinstall":` + avlJSON("echo "+s.phrase()) + `}}`
		},
	}
	for pname, place := range places {
		for sname, shape := range avlShapes() {
			t.Run(pname+"/"+sname, func(t *testing.T) {
				rel, body := place(shape)
				texts, fs := avlScan(t, rel, body)
				for name, text := range texts {
					if run := avlRun4(text, shape.words); run != "" {
						t.Errorf("%s: phrase words in a row printed: %q", name, run)
					}
				}
				named := false
				for _, f := range fs {
					if strings.HasPrefix(f.ID, "AR-") && f.Location == rel && strings.Contains(f.Evidence, "(긴 단어 나열을 가림)") {
						named = true
					}
				}
				if !named {
					t.Errorf("no AR finding at %s whose evidence says the word list was hidden: %+v", rel, fs)
				}
			})
		}
	}
}
