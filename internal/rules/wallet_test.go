package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// 이 규칙들은 줄 모양만 본다. 데이터 흐름이나 승인 절차는 보지 못하므로
// 결과는 모두 "의심"이고, 결과가 없다고 해서 문제가 없다는 뜻이 아니다.

var web3 = []string{"web3"}

func ruleHits(got map[string][]finding.Finding, id string) []string {
	var locs []string
	for loc, fs := range got {
		if hasID(fs, id) {
			locs = append(locs, loc)
		}
	}
	sort.Strings(locs)
	return locs
}

func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range embedded(t) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule %s", id)
	return Rule{}
}

func explainOf(t *testing.T, r Rule) string {
	t.Helper()
	b, err := aidefensekit.Data.ReadFile(r.Explain)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWalletRulesVulnerableExamples(t *testing.T) {
	cases := []struct {
		id, dir string
		stacks  []string
		want    []string
	}{
		{"WEB-001", "web/WEB-001", nil, []string{"index.html", "legacy.htm", "views/layout.ejs"}},
		{"WL-001", "wallet/WL-001", web3, []string{".env", "src/literal.ts", "src/mnemonic.ts", "src/signer.ts", "src/wallet.js"}},
		{"WL-002", "wallet/WL-002", web3, []string{"d7/forwarded.ts", "src/koa.ts", "src/relay.js", "src/sign.ts"}},
		{"WL-003", "wallet/WL-003", web3, []string{"src/auth.ts", "src/old.ts", "src/send.ts"}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got := allFindings(t, "../../testdata/rules/"+c.dir+"/vulnerable", c.stacks)
			if locs := ruleHits(got, c.id); strings.Join(locs, ",") != strings.Join(c.want, ",") {
				t.Fatalf("flagged %v, want %v", locs, c.want)
			}
			for loc, fs := range got {
				for _, f := range fs {
					if f.Confidence != finding.Suspect {
						t.Errorf("%s %s: confidence %v, want suspect", f.ID, loc, f.Confidence)
					}
					if f.ID == c.id && (f.ExplainKo == "" || f.Fix == "") {
						t.Errorf("%s %s: explain or fix missing", f.ID, loc)
					}
				}
			}
		})
	}
}

func TestWalletRulesSafeExamples(t *testing.T) {
	cases := []struct {
		id, dir string
		stacks  []string
	}{
		{"WEB-001", "web/WEB-001", nil},
		{"WL-001", "wallet/WL-001", web3},
		{"WL-002", "wallet/WL-002", web3},
		{"WL-003", "wallet/WL-003", web3},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if got := allFindings(t, "../../testdata/rules/"+c.dir+"/safe", c.stacks); len(got) != 0 {
				t.Errorf("safe examples were flagged: %+v", got)
			}
		})
	}
}

func TestWalletRulesNeedWeb3Stack(t *testing.T) {
	for _, id := range []string{"WL-001", "WL-002", "WL-003"} {
		for _, st := range [][]string{nil, {"nextjs"}, {"react"}, {"fastapi", "php"}} {
			got := allFindings(t, "../../testdata/rules/wallet/"+id+"/vulnerable", st)
			if locs := ruleHits(got, id); len(locs) != 0 {
				t.Errorf("%s ran with stacks %v: %v", id, st, locs)
			}
		}
	}
	// WEB-001 has no stack condition.
	for _, st := range [][]string{nil, {"php"}, {"nextjs", "web3"}} {
		got := allFindings(t, "../../testdata/rules/web/WEB-001/vulnerable", st)
		if len(ruleHits(got, "WEB-001")) != 3 {
			t.Errorf("WEB-001 with stacks %v: %v", st, ruleHits(got, "WEB-001"))
		}
	}
}

func scanText(t *testing.T, id, name, body string, stacks []string) []finding.Finding {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []finding.Finding
	for _, f := range allFindings(t, root, stacks)[name] {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

const scriptTag = `<script src="https://cdn.example.test/a.js"></script>`

func TestWEB001Shapes(t *testing.T) {
	flagged := []string{
		scriptTag,
		`<script src="http://cdn.example.test/a.js"></script>`,
		`<script src="//cdn.example.test/a.js"></script>`,
		`<SCRIPT SRC="HTTPS://cdn.example.test/a.js"></SCRIPT>`,
		`<script async defer src='https://cdn.example.test/a.js'></script>`,
		`<script type="module" src=https://cdn.example.test/a.js></script>`,
		`<script crossorigin="anonymous" src="https://cdn.example.test/a.js"></script>`,
	}
	for _, l := range flagged {
		if got := scanText(t, "WEB-001", "a.html", l+"\n", nil); len(got) != 1 {
			t.Errorf("not flagged: %s", l)
		}
	}
	clean := []string{
		`<script src="https://cdn.example.test/a.js" integrity="sha384-x" crossorigin="anonymous"></script>`,
		`<script integrity="sha384-x" src="https://cdn.example.test/a.js"></script>`,
		`<script src="/a.js"></script>`,
		`<script src="a.js"></script>`,
		`<script src="./a.js"></script>`,
		`<script src="../a.js"></script>`,
		`<script data-src="https://cdn.example.test/a.js"></script>`,
		`<img src="https://cdn.example.test/a.png">`,
		`<iframe src="https://cdn.example.test/a.html"></iframe>`,
		`<!-- <script src="https://cdn.example.test/a.js"></script> -->`,
	}
	for _, l := range clean {
		if got := scanText(t, "WEB-001", "a.html", l+"\n", nil); len(got) != 0 {
			t.Errorf("flagged: %s", l)
		}
	}
	// 한계(설명에 적혀 있다): 한 줄만 본다. `<script`와 `src`가 다른 줄에 있으면 태그를 알아보지 못해
	// 놓친다(미탐). `<script src=...`는 한 줄에 있고 integrity만 다음 줄에 있으면 오탐이 난다.
	split := "<script\n  src=\"https://cdn.example.test/a.js\"\n  integrity=\"sha384-x\"></script>\n"
	if got := scanText(t, "WEB-001", "a.html", split, nil); len(got) != 0 {
		t.Errorf("split tag: %+v", got)
	}
	both := "<script src=\"https://cdn.example.test/a.js\"\n  integrity=\"sha384-x\"></script>\n"
	if got := scanText(t, "WEB-001", "a.html", both, nil); len(got) != 1 {
		t.Errorf("src line without integrity on the same line is flagged although integrity is on the next line (documented false positive): %+v", got)
	}
	// 템플릿과 PHP 보기 파일도 HTML로 본다. 스크립트 파일은 보지 않는다.
	for _, name := range []string{"a.htm", "a.ejs", "a.hbs", "a.vue", "a.svelte", "a.phtml", "a.php", "a.erb", "a.twig", "a.jsp", "a.cshtml"} {
		if got := scanText(t, "WEB-001", name, scriptTag+"\n", nil); len(got) != 1 {
			t.Errorf("%s not scanned", name)
		}
	}
	for _, name := range []string{"a.js", "a.ts", "a.md", "a.json", "a.py"} {
		if got := scanText(t, "WEB-001", name, scriptTag+"\n", nil); len(got) != 0 {
			t.Errorf("%s scanned", name)
		}
	}
}

func TestWEB001Texts(t *testing.T) {
	r := ruleByID(t, "WEB-001")
	if r.severity > finding.Medium {
		t.Errorf("severity %v", r.severity)
	}
	ex := explainOf(t, r)
	for _, want := range []string{"CDN", "동적", "여러 줄", "상대 경로"} {
		if !strings.Contains(ex, want) {
			t.Errorf("explain lacks %q", want)
		}
	}
}

func TestWL002Shapes(t *testing.T) {
	flagged := []string{
		`const s = await wallet.signTransaction(req.body);`,
		`const s = await wallet.signTransaction(request.body.tx);`,
		`const s = await signer.signMessage(await res.json());`,
		`const s = await signer.signMessage((await response.json()).message);`,
		`await walletClient.sendTransaction(ctx.request.body);`,
		`await walletClient.sendTransaction({ ...req.body });`,
		`await walletClient.sendTransaction({ to: req.body.to, value: 1n });`,
		`await walletClient.signTypedData(req.body);`,
		`await walletClient.writeContract(req.body.call);`,
		`const s = await signer.signMessage(res.data.message);`,
		`const s = await signer.signMessage(await axios.get(url));`,
		`const s = await signer.signTransaction(await fetch(url).then((r) => r.json()));`,
	}
	for _, l := range flagged {
		if got := scanText(t, "WL-002", "src/a.ts", l+"\n", web3); len(got) != 1 {
			t.Errorf("not flagged: %s", l)
		}
	}
	clean := []string{
		`const tx = parseTx(req.body); await wallet.signTransaction(tx);`,
		`await wallet.signTransaction(schema.parse(req.body));`,
		`await wallet.signTransaction(validateTx(req.body));`,
		`await signer.signMessage(LOGIN_MESSAGE);`,
		`await signer.signMessage("hello");`,
		`await walletClient.sendTransaction({ to: ALLOWED_TO, value: 1n });`,
		`// await wallet.signTransaction(req.body);`,
		`* await wallet.signTransaction(req.body);`,
		`const sig = unrelatedSign(req.body);`,
		`const x = signTransactionLater(req.body);`,
		`const verified = verifyMessage(await res.json(), sig);`,
	}
	for _, l := range clean {
		if got := scanText(t, "WL-002", "src/a.ts", l+"\n", web3); len(got) != 0 {
			t.Errorf("flagged: %s", l)
		}
	}
}

func TestWL003IsReview(t *testing.T) {
	r := ruleByID(t, "WL-003")
	if r.severity > finding.Medium {
		t.Errorf("severity %v, want medium or lower", r.severity)
	}
	got := scanText(t, "WL-003", "src/a.ts", "await c.signAuthorization({ contractAddress });\n", web3)
	if len(got) != 1 {
		t.Fatalf("findings = %d", len(got))
	}
	f := got[0]
	if f.Confidence != finding.Suspect || f.Severity > finding.Medium {
		t.Errorf("%v %v", f.Confidence, f.Severity)
	}
	if !strings.Contains(f.ExplainKo, "검토 대상") || !strings.Contains(f.ExplainKo, "위험이 있다는 뜻이 아닙니다") {
		t.Errorf("explain doesn't say it's a review item:\n%s", f.ExplainKo)
	}
}

// D7: 외부 응답을 검증 없이 서명 함수에 넘기는 예제다. WL-002는 그 코드 모양을 알리는
// 신호일 뿐이며, 위조된 승인이나 서명 화면 조작을 탐지했다는 뜻이 아니다.
// 그런 공격은 줄 단위 규칙으로는 보이지 않는다.
func TestDrillD7(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/wallet/WL-002/vulnerable/d7", web3)
	if len(got) != 1 {
		t.Fatalf("files with findings = %v", got)
	}
	fs := got["forwarded.ts"]
	if len(fs) != 1 || fs[0].ID != "WL-002" || fs[0].Confidence != finding.Suspect {
		t.Fatalf("findings = %+v", fs)
	}
	if strings.Contains(fs[0].ExplainKo, "탐지했") {
		t.Errorf("explain claims detection")
	}
}

func TestWL004IsReserved(t *testing.T) {
	for _, r := range embedded(t) {
		if r.ID == "WL-004" {
			t.Fatal("WL-004 was dropped (see docs/usage.md) and its ID is reserved")
		}
	}
	b, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "WL-004") {
		t.Error("docs/usage.md must say why WL-004 is not a rule")
	}
}

// 개인 키 값은 어느 출력에도 나오면 안 된다. 값은 시험 안에서 조립하고 파일로 두지 않는다.
func canaryKey(seed string) string { return "0x" + strings.Repeat(seed, 16) }

func canaryPhrase(seed string) string {
	words := append([]string{"alpha", "bravo", "cobalt", "delta", "ember", "falcon"},
		"garnet", "harbor", "island", "jungle", "kernel", "lumen")
	for i := range words {
		words[i] = seed + words[i]
	}
	return strings.Join(words, " ")
}

type canaryShape struct{ name, file, line string }

func canaryShapes(k, p string) []canaryShape {
	raw := strings.TrimPrefix(k, "0x")
	return []canaryShape{
		{"env", ".env", "PRIVATE_KEY=" + k},
		{"env raw hex", ".env", "PRIVATE_KEY=" + raw},
		{"env export quoted", ".env.local", `export DEPLOYER_PRIVATE_KEY="` + k + `"`},
		{"env single quoted", ".env.production", "OPS_PRIVATE_KEY='" + k + "'"},
		{"env mnemonic", ".env", "MNEMONIC=" + p},
		{"env mnemonic quoted", ".env", `WALLET_MNEMONIC="` + p + `"`},
		{"const", "src/a.ts", `const PRIVATE_KEY = "` + k + `";`},
		{"object", "src/b.ts", `const cfg = { privateKey: "` + k + `", rpc: 1 };`},
		{"wallet", "src/c.ts", `const w = new Wallet("` + k + `", provider);`},
		{"ethers wallet", "src/d.js", `const w = new ethers.Wallet('` + k + `');`},
		{"account", "src/e.ts", "const a = privateKeyToAccount(`" + k + "`);"},
		{"phrase", "src/f.ts", `const w = Wallet.fromPhrase("` + p + `");`},
		{"after other code", "src/g.ts", `const r = await sign(1, 2); const w = new Wallet("` + k + `"); log(r);`},
	}
}

func TestWL001NeverPrintsKeyValues(t *testing.T) {
	k, p := canaryKey("9f3a"), canaryPhrase("zq")
	for _, c := range canaryShapes(k, p) {
		t.Run(c.name, func(t *testing.T) {
			got := scanText(t, "WL-001", c.file, "// header\n"+c.line+"\n", web3)
			if len(got) != 1 {
				t.Fatalf("findings = %d for %q", len(got), c.file)
			}
			f := got[0]
			b, _ := json.Marshal(f)
			all := f.Evidence + "\n" + f.Fingerprint + "\n" + string(b)
			for _, s := range []string{k, strings.TrimPrefix(k, "0x"), k[:8], "9f3a9f3a", p, "zqalpha", "zq"} {
				if strings.Contains(all, s) {
					t.Errorf("%q leaked: %s", s, all)
				}
			}
			if f.Line != 2 || f.Evidence == "" {
				t.Errorf("line %d evidence %q", f.Line, f.Evidence)
			}
		})
	}
}

// 지문은 값에서 만들지 않는다: 값만 다른 같은 줄은 지문이 같고, 줄의 모양이 다르면 지문이 다르다.
func TestWL001FingerprintIgnoresValue(t *testing.T) {
	a := scanText(t, "WL-001", ".env", "PRIVATE_KEY="+canaryKey("1b2c")+"\n", web3)
	b := scanText(t, "WL-001", ".env", "PRIVATE_KEY="+canaryKey("7d8e")+"\n", web3)
	c := scanText(t, "WL-001", ".env", "OTHER_PRIVATE_KEY="+canaryKey("1b2c")+"\n", web3)
	if len(a) != 1 || len(b) != 1 || len(c) != 1 {
		t.Fatalf("%d %d %d", len(a), len(b), len(c))
	}
	if a[0].Fingerprint != b[0].Fingerprint {
		t.Error("fingerprint depends on the key value")
	}
	if a[0].Fingerprint == c[0].Fingerprint {
		t.Error("fingerprint ignores the variable name")
	}
	raw := finding.MakeFingerprint("WL-001", ".env", "PRIVATE_KEY="+canaryKey("1b2c"))
	if a[0].Fingerprint == raw {
		t.Error("fingerprint is the hash of the raw line")
	}
}

// 줄이 아주 길어도(번들 파일 등) 값은 가려진다.
func TestWL001LongLineStaysMasked(t *testing.T) {
	k := canaryKey("5e6f")
	line := strings.Repeat("a=1;", 100) + `new Wallet("` + k + `")` + strings.Repeat("b=2;", 100)
	got := scanText(t, "WL-001", "src/bundle.js", line+"\n", web3)
	if len(got) != 1 {
		t.Fatalf("findings = %d", len(got))
	}
	if strings.Contains(got[0].Evidence, "5e6f5e6f") || strings.Contains(got[0].Evidence, k[:6]) {
		t.Errorf("leaked: %s", got[0].Evidence)
	}
}

func TestWL001Exclusions(t *testing.T) {
	line := "const k = process.env.PRIVATE_KEY;\n"
	skipped := []string{
		"hardhat.config.ts", "hardhat.config.js", "contracts/hardhat.config.cjs",
		"scripts/deploy.js", "script/Deploy.ts", "packages/a/scripts/seed.ts", "deploy/01_deploy.ts",
		"test/a.ts", "tests/a.js", "src/__tests__/a.ts", "src/a.test.ts", "src/a.spec.js", "src/a.test.tsx",
		"truffle-config.js", ".env.example", ".env.sample", ".env.template",
	}
	for _, name := range skipped {
		if got := scanText(t, "WL-001", name, line, web3); len(got) != 0 {
			t.Errorf("%s was scanned", name)
		}
	}
	for _, name := range []string{"src/a.ts", "server/sign.js", "app/api/route.ts", "lib/scripts-helper.ts", "src/testing.ts"} {
		if got := scanText(t, "WL-001", name, line, web3); len(got) != 1 {
			t.Errorf("%s was not scanned", name)
		}
	}
	ex := explainOf(t, ruleByID(t, "WL-001"))
	for _, want := range []string{"hardhat.config", "scripts", "test"} {
		if !strings.Contains(ex, want) {
			t.Errorf("explain doesn't state the exclusion %q", want)
		}
	}
}

func TestWL001Shapes(t *testing.T) {
	flagged := []string{
		`const a = privateKeyToAccount(process.env.TREASURY_PRIVATE_KEY);`,
		`const a = privateKeyToAccount(process.env.SIGNER);`,
		`const a = privateKeyToAccount(import.meta.env.VITE_KEY);`,
		`const w = new ethers.Wallet(process.env.OPS_KEY, provider);`,
		`const w = new Wallet("not-a-real-key", provider);`,
		`const k = process.env["PRIVATE_KEY"];`,
		`const k = process.env.WALLET_MNEMONIC;`,
		`const k = process.env.SEED_PHRASE;`,
		`const k = import.meta.env.VITE_PRIVATE_KEY;`,
		`const w = Wallet.fromPhrase(process.env.PHRASE);`,
	}
	for _, l := range flagged {
		if got := scanText(t, "WL-001", "src/a.ts", l+"\n", web3); len(got) != 1 {
			t.Errorf("not flagged: %s", l)
		}
	}
	clean := []string{
		`const w = new Wallet(signerKey, provider);`,
		`const w = new Wallet(await kms.getKey(), provider);`,
		`const a = privateKeyToAccount(key);`,
		`const w = Wallet.createRandom();`,
		`const url = process.env.RPC_URL;`,
		`const pub = process.env.PUBLIC_KEY;`,
		`const w = new Walleted("x");`,
		`// const k = process.env.PRIVATE_KEY;`,
		`import { privateKeyToAccount } from "viem/accounts";`,
	}
	for _, l := range clean {
		if got := scanText(t, "WL-001", "src/a.ts", l+"\n", web3); len(got) != 0 {
			t.Errorf("flagged: %s", l)
		}
	}
	envClean := []string{"PRIVATE_KEY=", "PRIVATE_KEY=your_key_here", "PRIVATE_KEY=<your key>", "PRIVATE_KEY=${KEY_FROM_VAULT}", "# PRIVATE_KEY=abc", "RPC_URL=https://rpc.example.test", "PUBLIC_KEY=abc"}
	for _, l := range envClean {
		if got := scanText(t, "WL-001", ".env", l+"\n", web3); len(got) != 0 {
			t.Errorf("flagged env line: %s", l)
		}
	}
}

// 파일이 다르면 같은 줄이어도 따로 나온다.
func TestWL001ReportsEachFile(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"a/.env", "b/.env"} {
		p := filepath.Join(root, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("PRIVATE_KEY=not-a-real-value\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := allFindings(t, root, web3)
	if len(got["a/.env"]) != 1 || len(got["b/.env"]) != 1 || got["a/.env"][0].Fingerprint == got["b/.env"][0].Fingerprint {
		t.Errorf("%+v", got)
	}
}

// web3가 다른 스택과 함께 있어도 JS/TS 파일에는 web3 안내가 나온다 (다른 언어의 안내가 아니다).
func TestWalletFixGuideWithOtherStacks(t *testing.T) {
	combos := [][]string{{"web3"}, {"nextjs", "web3"}, {"react", "web3"}, {"fastapi", "web3"}, {"php", "web3"}, {"fastapi", "nextjs", "php", "react", "supabase", "web3"}}
	body := map[string]string{
		"WL-001": "const k = process.env.PRIVATE_KEY;\n",
		"WL-002": "await w.signTransaction(req.body);\n",
		"WL-003": "await w.signAuthorization({ a });\n",
	}
	for id, text := range body {
		for _, st := range combos {
			got := scanText(t, id, "src/a.ts", text, st)
			if len(got) != 1 {
				t.Fatalf("%s %v: %d findings", id, st, len(got))
			}
			if !strings.HasPrefix(got[0].Fix, "# Web3") {
				t.Errorf("%s %v: guide = %.30q", id, st, got[0].Fix)
			}
		}
	}
	// WEB-001은 스택과 상관없이 같은 안내가 나온다.
	for _, st := range append(combos, nil) {
		got := scanText(t, "WEB-001", "a.html", scriptTag+"\n", st)
		if len(got) != 1 || !strings.HasPrefix(got[0].Fix, "# HTML") {
			t.Errorf("WEB-001 %v: %+v", st, got)
		}
	}
}

func TestWalletTextsAvoidForbiddenWords(t *testing.T) {
	for _, id := range []string{"WEB-001", "WL-001", "WL-002", "WL-003"} {
		r := ruleByID(t, id)
		texts := []string{r.Title, explainOf(t, r)}
		dir := strings.TrimSuffix(r.Fix, "/")
		ents, err := aidefensekit.Data.ReadDir(dir)
		if err != nil || len(ents) == 0 {
			t.Fatalf("%s: no fix guide in %s", id, dir)
		}
		for _, e := range ents {
			g, _ := aidefensekit.Data.ReadFile(dir + "/" + e.Name())
			texts = append(texts, string(g))
		}
		for _, s := range texts {
			for _, w := range []string{"막는다", "안전", "방어한다"} {
				if strings.Contains(s, w) {
					t.Errorf("%s: contains %q", id, w)
				}
			}
		}
	}
}

func TestExcludeFilesKey(t *testing.T) {
	rule := okRule + "  exclude_files: [\"**/skip/**\"]\n"
	rs, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(rule)}})
	if err != nil || len(rs) != 1 {
		t.Fatalf("err=%v", err)
	}
	if matchesFiles(rs[0], "skip/a.py") || !matchesFiles(rs[0], "keep/a.py") {
		t.Error("exclude_files not applied")
	}
	bad := strings.Replace(rule, `"**/skip/**"`, `"[a-"`, 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(bad)}}); err == nil {
		t.Error("bad exclude_files pattern accepted")
	}
}
