package rules

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

var baseWords = append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
	"glide", "pencil", "north", "spring", "cabin", "onion")
var koreanWords = []string{"가격", "가끔", "가난", "가능", "가득", "가르침", "가뭄", "가방", "가상", "가슴", "가위", "가을"}

type wordShape struct {
	name   string
	tokens []string // 출력에 나오면 안 되는 단어
	text   string
}

func titleCase(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

func wordShapes() []wordShape {
	var out []wordShape
	add := func(name string, words []string, sep string) {
		out = append(out, wordShape{name, words, strings.Join(words, sep)})
	}
	add("lower", baseWords, " ")
	var up, ti, numbered, paren []string
	for i, w := range baseWords {
		up = append(up, strings.ToUpper(w))
		ti = append(ti, titleCase(w))
		numbered = append(numbered, string(rune('1'+i%9))+"."+w)
		paren = append(paren, string(rune('1'+i%9))+") "+w)
	}
	add("upper", up, " ")
	add("title", ti, " ")
	add("tabs", baseWords, "\t")
	add("nbsp", baseWords, " ")
	add("commas", baseWords, ",")
	add("comma space", baseWords, ", ")
	add("eleven words", baseWords[:11], " ")
	out = append(out, wordShape{"numbered dot", baseWords, strings.Join(numbered, " ")})
	out = append(out, wordShape{"numbered paren", baseWords, strings.Join(paren, " ")})
	add("korean", koreanWords, " ")
	add("korean commas", koreanWords, ", ")
	return out
}

// 다른 규칙(RE-001)이 걸리는 줄에서 단어 나열이 주석에도 따옴표 안에도 값으로도 나오면 안 된다.
func TestWordSequencesNeverPrintedWhole(t *testing.T) {
	for _, sh := range wordShapes() {
		lines := []string{
			"VITE_PRIVATE_KEY=abcdefgh # " + sh.text,
			"VITE_PRIVATE_KEY=abcdefgh // " + sh.text,
			`VITE_SECRET_KEY="` + sh.text + `"`,
			"VITE_SECRET_KEY=" + sh.text,
			"VITE_SECRET_KEY='" + sh.text + "' # " + sh.text,
		}
		for _, l := range lines {
			got := scanText(t, "RE-001", ".env", l+"\n", []string{"react"})
			if len(got) != 1 {
				t.Errorf("%s %.40q: findings = %d", sh.name, l, len(got))
				continue
			}
			b, _ := json.Marshal(got[0])
			for _, w := range sh.tokens {
				if strings.Contains(got[0].Evidence, w) || strings.Contains(string(b), w) {
					t.Errorf("%s %.40q: word %q printed: %q", sh.name, l, w, got[0].Evidence)
					break
				}
			}
			// .env 값은 모양과 상관없이 전부 가려진다(주석도 나오지 않는다).
			if !strings.Contains(got[0].Evidence, "=****") {
				t.Errorf("%s: .env value not masked whole: %q", sh.name, got[0].Evidence)
			}
		}
	}
}

func TestShortOrBrokenSequencesAreKept(t *testing.T) {
	for _, s := range []string{
		strings.Join(baseWords[:10], " "), // 10개
		// 마침표도 구분 문자다. 9글자 이상 단어나 한 글자 단어가 끼면 끊긴다.
		strings.Join(baseWords[:6], " ") + " longwordlong " + strings.Join(baseWords[6:], " "),
		strings.Join(baseWords[:6], " ") + " a " + strings.Join(baseWords[6:], " "),
	} {
		if finding.ContainsKeyMaterial(s) {
			t.Errorf("flagged: %q", s)
		}
	}
	if finding.ContainsKeyMaterial(strings.Repeat("longwordlong ", 20)) {
		t.Error("words longer than 8 letters counted")
	}
}

func TestWordRunScanIsLinear(t *testing.T) {
	big := strings.Repeat("zoo, ", 200000) + strings.Repeat("a1 ", 100000) + strings.Repeat("0123456789abcdef", 50000)
	start := time.Now()
	finding.ScrubKeyMaterial(big)
	finding.ContainsKeyMaterial(big)
	_ = maskEvidence(big)
	if d := time.Since(start); d > maskStallLimit {
		t.Errorf("took %v", d)
	}
}

// 한 줄에 닫히지 않은 따옴표가 있는 값은 따옴표 뒤를 모두 가린다.
func TestUnclosedQuoteMasksTheRest(t *testing.T) {
	first := strings.Join(baseWords[:6], " ")
	for _, l := range []string{
		`VITE_SECRET="` + first,
		`VITE_SECRET='` + first,
		"VITE_SECRET=`" + first,
		`const VITE_SECRET = "` + first,
	} {
		got := maskEvidence(l)
		for _, w := range baseWords[:6] {
			if strings.Contains(got, w) {
				t.Errorf("%q -> %q", l, got)
				break
			}
		}
	}
	if got := maskEvidence(`VITE_SECRET="abc`); !strings.HasSuffix(got, `"****`) {
		t.Errorf("got %q", got)
	}
	// 닫힌 따옴표는 이전과 같다.
	if got := maskEvidence(`API_TOKEN = "hunter2"`); got != `API_TOKEN = "****"` {
		t.Errorf("closed quote changed: %q", got)
	}
}

// 키 모양이 든 줄은 줄 번호가 지문에 들어가 같은 모양의 다른 줄이 합쳐지지 않는다.
func TestKeyShapedLinesAreEachReported(t *testing.T) {
	k1, k2 := "0x"+strongKey("r2-a"), "0x"+strongKey("r2-b")
	p1, p2 := strongPhrase(), strings.Join(append([]string{"fox"}, baseWords[1:]...), " ")
	cases := []struct {
		id, file string
		stacks   []string
		a, b     string
	}{
		{"RE-001", ".env", []string{"react"}, "VITE_PRIVATE_KEY=" + k1, "VITE_PRIVATE_KEY=" + k2},
		{"WL-002", "src/a.ts", web3, `await w.signTransaction(req.body, new Wallet("` + k1 + `"));`, `await w.signTransaction(req.body, new Wallet("` + k2 + `"));`},
		{"WL-002", "src/b.ts", web3, `await w.signTransaction(req.body); // ` + p1, `await w.signTransaction(req.body); // ` + p2},
		{"WL-002", "src/c.ts", web3, `await w.signTransaction(req.body); // ` + p1, `await w.signTransaction(req.body); // ` + p1},
	}
	for _, c := range cases {
		got := scanText(t, c.id, c.file, c.a+"\n"+c.b+"\n", c.stacks)
		if len(got) != 2 {
			t.Errorf("%s %.50q: reported %d lines, want 2", c.id, c.a, len(got))
			continue
		}
		if got[0].Fingerprint == got[1].Fingerprint {
			t.Errorf("%s: same fingerprint", c.id)
		}
		for _, f := range got {
			b, _ := json.Marshal(f)
			if l := leaked(f.Evidence+string(b), k1, append(strongWords, "fox")); len(l) > 0 {
				t.Errorf("%s leaked %v", c.id, l)
			}
		}
	}
}
