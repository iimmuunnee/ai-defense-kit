package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 값은 모두 시험 안에서 조립한다. 파일로 저장하지 않는다.

// strongKey는 해시에서 만든 64자리 16진수(높은 엔트로피)다.
func strongKey(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// 첫 단어가 세 글자인 12단어 구문.
var strongWords = append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
	"glide", "pencil", "north", "spring", "cabin", "onion")

func strongPhrase() string { return strings.Join(strongWords, " ") }

var longHex = regexp.MustCompile(`[0-9a-f]{16,}`)

// leaked는 출력 text에 남은 키 조각과 단어를 모아 돌려준다.
// 지문과 해시는 16자리 이상 16진수 덩어리라 4글자 조각 비교에서는 뺀다(전체 조각 비교는 따로 한다).
func leaked(text string, key string, words []string) []string {
	var out []string
	raw := strings.TrimPrefix(key, "0x")
	if key != "" {
		if strings.Contains(text, raw) {
			out = append(out, "full key")
		}
		for i := 0; i+16 <= len(raw); i++ {
			if strings.Contains(text, raw[i:i+16]) {
				out = append(out, "16-char piece "+raw[i:i+16])
				break
			}
		}
		clean := longHex.ReplaceAllString(text, "")
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(clean, key[i:i+4]) {
				out = append(out, "4-char piece "+key[i:i+4])
			}
		}
	}
	for _, w := range words {
		if strings.Contains(text, w) {
			out = append(out, "word "+w)
		}
	}
	return out
}

type strongShape struct{ name, file, line string }

func strongShapes(key0x, phrase string) []strongShape {
	raw := strings.TrimPrefix(key0x, "0x")
	return []strongShape{
		{"env 0x key", ".env", "PRIVATE_KEY=" + key0x},
		{"env raw key", ".env", "PRIVATE_KEY=" + raw},
		{"env key with apostrophe comment", ".env", "PRIVATE_KEY=" + key0x + " # don't share"},
		{"env quoted key", ".env", `PRIVATE_KEY="` + key0x + `"`},
		{"env phrase quoted", ".env", `MNEMONIC="` + phrase + `"`},
		{"env phrase bare", ".env", "MNEMONIC=" + phrase},
		{"env phrase apostrophe comment", ".env", "MNEMONIC=" + phrase + " # don't share"},
		{"env phrase paren", ".env", "MNEMONIC=" + phrase + " (backup)"},
		{"env phrase export", ".env.local", "export SEED_PHRASE=" + phrase},
		{"code phrase unclosed template", "src/t.ts", "const MNEMONIC = `" + phrase},
		{"code fromPhrase unclosed template", "src/u.ts", "const w = Wallet.fromPhrase(`" + phrase},
		{"code fromPhrase", "src/v.ts", `const w = Wallet.fromPhrase("` + phrase + `");`},
		{"code bare fromPhrase", "src/w.ts", `const w = fromPhrase("` + phrase + `");`},
		{"code wallet 0x", "src/x.ts", `const w = new Wallet("` + key0x + `", provider);`},
		{"code account raw", "src/y.ts", `const a = privateKeyToAccount('` + raw + `');`},
		{"code const key", "src/z.ts", `const PRIVATE_KEY = "` + key0x + `"; // don't`},
	}
}

func TestWL001NeverPrintsStrongKeyMaterial(t *testing.T) {
	key := "0x" + strongKey("canary-one")
	for _, c := range strongShapes(key, strongPhrase()) {
		t.Run(c.name, func(t *testing.T) {
			got := scanText(t, "WL-001", c.file, "// header\n"+c.line+"\n", web3)
			if len(got) != 1 {
				t.Fatalf("findings = %d", len(got))
			}
			b, _ := json.Marshal(got[0])
			if l := leaked(got[0].Evidence+"\n"+string(b), key, strongWords); len(l) > 0 {
				t.Errorf("leaked %v: evidence %q", l, got[0].Evidence)
			}
			if raw := finding.MakeFingerprint("WL-001", c.file, c.line); got[0].Fingerprint == raw {
				t.Error("fingerprint is the hash of the raw line")
			}
		})
	}
}

// 같은 줄에 걸리는 다른 규칙도 키와 구문을 보여 주지 않고, 지문도 원문 줄에서 만들지 않는다.
func TestOtherRulesNeverPrintKeyMaterialOnTheSameLine(t *testing.T) {
	key := "0x" + strongKey("canary-two")
	raw := strings.TrimPrefix(key, "0x")
	cases := []struct{ id, file, line string }{
		{"RE-001", ".env", "VITE_PRIVATE_KEY=" + key},
		{"RE-001", ".env", "VITE_PRIVATE_KEY=" + raw},
		{"RE-001", ".env", "VITE_PRIVATE_KEY=" + strongPhrase() + " # don't share"},
		{"RE-001", ".env", "REACT_APP_SECRET=" + strongPhrase() + " (backup)"},
		{"WL-002", "src/a.ts", `await w.signTransaction(req.body, new Wallet("` + key + `"));`},
		{"WL-002", "src/b.ts", `await w.signMessage(req.body, privateKeyToAccount('` + raw + `'));`},
		{"WL-003", "src/c.ts", `await c.signAuthorization({ account: privateKeyToAccount("` + key + `") });`},
		{"WL-003", "src/d.ts", `const a = await c.signAuthorization({ w: new Wallet("` + key + `") });`},
	}
	for _, c := range cases {
		got := scanText(t, c.id, c.file, c.line+"\n", []string{"react", "web3"})
		if len(got) != 1 {
			t.Errorf("%s %q: findings = %d", c.id, c.line, len(got))
			continue
		}
		b, _ := json.Marshal(got[0])
		if l := leaked(got[0].Evidence+"\n"+string(b), key, strongWords); len(l) > 0 {
			t.Errorf("%s leaked %v: %q", c.id, l, got[0].Evidence)
		}
		if got[0].Fingerprint == finding.MakeFingerprint(c.id, c.file, c.line) {
			t.Errorf("%s: fingerprint made from the raw line", c.id)
		}
	}
	// 키 모양이 없는 줄도 지문은 보이는 근거와 순번에서 만들고 원문 줄에서 만들지 않는다.
	plain := scanText(t, "RE-001", ".env", "VITE_API_SECRET=abcdefghijkl\n", []string{"react"})
	if len(plain) != 1 || plain[0].Fingerprint != finding.MakeMaskedFingerprint("RE-001", ".env", plain[0].Evidence, 0) ||
		plain[0].Fingerprint == finding.MakeFingerprint("RE-001", ".env", "VITE_API_SECRET=abcdefghijkl") {
		t.Errorf("plain fingerprint: %+v", plain)
	}
}

func TestHideEvidenceFailsClosed(t *testing.T) {
	key := "0x" + strongKey("canary-three")
	cases := map[string]string{
		"PRIVATE_KEY=" + key:                                  "PRIVATE_KEY=****",
		"export DEPLOYER_PRIVATE_KEY=\"" + key + "\"":         "DEPLOYER_PRIVATE_KEY=****",
		"MNEMONIC=" + strongPhrase() + " (backup)":            "MNEMONIC=****",
		"const w = new ethers.Wallet(\"" + key + "\", p);":    "ethers.Wallet(****",
		"const k = process.env.TREASURY_PRIVATE_KEY || 'x';":  "process.env.TREASURY_PRIVATE_KEY ****",
		"const a = 'q'; const w = new Wallet('" + key + "');": "Wallet(****",
		`const cfg = { privateKey: "` + key + `" };`:          "privateKey:****",
	}
	for in, want := range cases {
		if got := hideEvidence(in); got != want {
			t.Errorf("hideEvidence(%.40q) = %q, want %q", in, got, want)
		}
		if l := leaked(hideEvidence(in), key, strongWords); len(l) > 0 {
			t.Errorf("leaked %v", l)
		}
	}
	if got := hideEvidence("nothing to see here"); got != "****" {
		t.Errorf("no name: %q", got)
	}
}

// 값만 다르고 이름이 같은 줄 두 개는 따로 나오고, 지문에는 값이 들어가지 않는다.
func TestWL001SameNameOnDifferentLines(t *testing.T) {
	a, b := "0x"+strongKey("k1"), "0x"+strongKey("k2")
	got := scanText(t, "WL-001", ".env", "PRIVATE_KEY="+a+"\nPRIVATE_KEY="+b+"\n", web3)
	if len(got) != 2 || got[0].Fingerprint == got[1].Fingerprint {
		t.Fatalf("%+v", got)
	}
	// 같은 줄 번호이면 값이 달라도 지문이 같다.
	x := scanText(t, "WL-001", ".env", "PRIVATE_KEY="+a+"\n", web3)
	y := scanText(t, "WL-001", ".env", "PRIVATE_KEY="+b+"\n", web3)
	if x[0].Fingerprint != y[0].Fingerprint {
		t.Error("fingerprint depends on the value")
	}
}

func TestMaskEvidenceKeyMaterial(t *testing.T) {
	key := "0x" + strongKey("canary-four")
	raw := strings.TrimPrefix(key, "0x")
	lines := []string{
		"VITE_PRIVATE_KEY=" + key,
		"PRIVATE_KEY=" + raw,
		`const w = new Wallet("` + key + `");`,
		`MNEMONIC="` + strongPhrase() + `"`,
		"MNEMONIC=" + strongPhrase() + " # it's mine",
		"MNEMONIC=" + strongPhrase() + " (backup)",
		"const m = `" + strongPhrase(),
		"x = " + key + " and " + raw,
	}
	for _, l := range lines {
		if got := maskEvidence(l); len(leaked(got, key, strongWords)) > 0 {
			t.Errorf("maskEvidence(%.30q) = %q", l, got)
		}
	}
	// 키 모양이 아닌 값은 이전처럼 앞 4글자가 남는다.
	if got := maskEvidence("k = abcdefghijklmnop1234"); got != "k = abcd****" {
		t.Errorf("other secrets changed: %q", got)
	}
}

func TestWL001ExclusionsAreAnchored(t *testing.T) {
	line := "const k = process.env.PRIVATE_KEY;\n"
	for _, name := range []string{"src/services/test/a.ts", "app/api/deploy/route.ts", "src/scripts/a.ts", "lib/deploy/a.ts", "src/tests/a.ts", "src/script/a.ts"} {
		if got := scanText(t, "WL-001", name, line, web3); len(got) != 1 {
			t.Errorf("%s should be scanned", name)
		}
	}
	for _, name := range []string{"scripts/a.ts", "script/a.ts", "deploy/a.ts", "test/a.ts", "tests/a.ts", "packages/api/scripts/a.ts", "apps/web/test/a.ts", "apps/web/deploy/a.ts", "src/__tests__/a.ts"} {
		if got := scanText(t, "WL-001", name, line, web3); len(got) != 0 {
			t.Errorf("%s should be skipped", name)
		}
	}
	ex := explainOf(t, ruleByID(t, "WL-001"))
	if !strings.Contains(ex, "packages/*") || !strings.Contains(ex, "apps/*") {
		t.Error("explain doesn't state where the folders are matched")
	}
}

func TestWL001RegexAndSkipFixes(t *testing.T) {
	// 첫 단어가 replace인 구문은 예시 줄로 보고 건너뛰지 않는다.
	ph := "replace " + strings.Join(strongWords[1:], " ")
	if got := scanText(t, "WL-001", ".env", "MNEMONIC="+ph+"\n", web3); len(got) != 1 {
		t.Errorf("mnemonic starting with replace: %d", len(got))
	}
	for _, l := range []string{"PRIVATE_KEY=REPLACE_ME", "PRIVATE_KEY=replace-me", "PRIVATE_KEY=changeme", "PRIVATE_KEY=your_key_here", "MNEMONIC=<phrase>"} {
		if got := scanText(t, "WL-001", ".env", l+"\n", web3); len(got) != 0 {
			t.Errorf("placeholder flagged: %s", l)
		}
	}
	// 줄에 fromPhrase(만 있어도 정규식 실행 조건을 통과한다.
	if got := scanText(t, "WL-001", "src/a.ts", `const w = fromPhrase("not a real phrase");`+"\n", web3); len(got) != 1 {
		t.Errorf("bare fromPhrase: %d", len(got))
	}
}

func TestWEB001IntegrityNeedsTheAttribute(t *testing.T) {
	flagged := []string{
		`<script src="https://cdn.example.test/a.js" data-integrity="x"></script>`,
		`<script src="https://cdn.example.test/a.js" data-integrity = "x"></script>`,
	}
	for _, l := range flagged {
		if got := scanText(t, "WEB-001", "a.html", l+"\n", nil); len(got) != 1 {
			t.Errorf("not flagged: %s", l)
		}
	}
	if got := scanText(t, "WEB-001", "a.vue", `<script :integrity="h" src="https://cdn.example.test/a.js"></script>`+"\n", nil); len(got) != 0 {
		t.Errorf("bound integrity attribute flagged")
	}
	// 설명에 적은 놓치는 경우를 시험으로 고정한다.
	miss := map[string]string{
		"multi-line": "<script\n  src=\"https://cdn.example.test/a.js\"></script>\n",
		"mixed case": `<sCrIpT src="https://cdn.example.test/a.js"></sCrIpT>` + "\n",
		"second tag": `<script src="/a.js" integrity="x"></script><script src="https://cdn.example.test/b.js"></script>` + "\n",
	}
	for name, body := range miss {
		if got := scanText(t, "WEB-001", "a.html", body, nil); len(got) != 0 {
			t.Errorf("%s: documented miss now found, update the explain: %+v", name, got)
		}
	}
	ex := explainOf(t, ruleByID(t, "WEB-001"))
	for _, want := range []string{"여러 줄", "<sCrIpT", "두 번째", "놓칩니다"} {
		if !strings.Contains(ex, want) {
			t.Errorf("explain lacks %q", want)
		}
	}
	if strings.Contains(ex, "integrity`가 다른 줄에 있어도 결과가 나올 수 있습니다") {
		t.Error("explain keeps the misleading sentence")
	}
}

func TestWL002TypedDataThirdArgument(t *testing.T) {
	flagged := []string{
		`const s = await wallet.signTypedData(domain, types, req.body);`,
		`const s = await wallet.signTypedData(domain, { Mail: [{ name: "a", type: "string" }] }, await res.json());`,
		`const s = await wallet.signTypedData(domain, types, ctx.request.body.value);`,
	}
	for _, l := range flagged {
		if got := scanText(t, "WL-002", "src/a.ts", l+"\n", web3); len(got) != 1 {
			t.Errorf("not flagged: %s", l)
		}
	}
	clean := []string{
		`const s = await wallet.signTypedData(domain, types, value);`,
		`const s = await wallet.signTypedData(domain, types, schema.parse(req.body));`,
	}
	for _, l := range clean {
		if got := scanText(t, "WL-002", "src/a.ts", l+"\n", web3); len(got) != 0 {
			t.Errorf("flagged: %s", l)
		}
	}
}

func TestWL001ExplainStatesWhatIsPrinted(t *testing.T) {
	// 자세한 내용은 docs/usage.md로 옮겼다(설명에는 2~3줄과 그 문서 안내만 남김).
	usage, err := os.ReadFile(filepath.Join("..", "..", "docs", "usage.md"))
	if err != nil {
		t.Fatal(err)
	}
	ex := explainOf(t, ruleByID(t, "WL-001")) + "\n" + string(usage)
	if strings.Contains(ex, "이 도구는 값을 출력하지 않습니다") {
		t.Error("explain keeps the unconditional claim")
	}
	for _, want := range []string{"이름과 `****`", "접두사 없이", "64자리", "11개", "(주석 생략)", "`.env` 파일", "닫히지 않은 따옴표", "이전 방식",
		// 따옴표와 상관없는 주석 자르기, .env* 파일, 넓은 구분 문자, 보장하지 않는 것
		"따옴표와 상관없이", "`.envrc`", "`=`이 없는 줄", "경로", "UPPER_SNAKE", "보장하지 않습니다", "쓰인 그대로 나올 수 있습니다", "앞 4글자",
		// 이름 자리, 이스케이프, 200글자 경계, 다른 검사기, 보장하지 않는 것
		"올바른 환경 변수 이름", "`%20`", "`&nbsp;`", "200글자", "`AR-*`", "`SB-001`", "중국어", "`ab://`"} {
		if !strings.Contains(ex, want) {
			t.Errorf("explain lacks %q", want)
		}
	}
}

func TestWL003GuideMentionsNamesAndChainID(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "fixes", "WL-003", "web3.md"))
	if err != nil {
		t.Fatal(err)
	}
	g := string(b)
	for _, want := range []string{"contractAddress", "`address`", "확인 필요", "체인 ID가 0", "0 주소"} {
		if !strings.Contains(g, want) {
			t.Errorf("guide lacks %q", want)
		}
	}
}
