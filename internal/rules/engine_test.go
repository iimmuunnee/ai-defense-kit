package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func embedded(t *testing.T) []Rule {
	t.Helper()
	rs, err := Load(aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestPortOneVulnerable(t *testing.T) {
	fs, _, err := Evaluate("../../testdata/rules/KR-PAY-002/vulnerable", []string{"fastapi"}, embedded(t), aidefensekit.Data)
	// vulnerable/ holds a Python and a TypeScript receiver: one finding each.
	if err != nil || len(fs) != 2 {
		t.Fatalf("err=%v findings=%v", err, fs)
	}
	var f finding.Finding
	for _, c := range fs {
		if c.Location == "app/webhook.py" {
			f = c
		}
	}
	if f.ID != "KR-PAY-002" || f.Severity != finding.High || f.Confidence != finding.Suspect ||
		f.Location != "app/webhook.py" || f.Line <= 0 {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Title != "포트원 웹훅 검증 누락" || f.ExplainKo == "" || !strings.Contains(f.Fix, "FastAPI") ||
		len(f.References) != 4 || len(f.Mappings) != 1 || f.Mappings[0] != (finding.Mapping{ID: "ISMSP-2.10.4"}) || f.Kind != "KR-PAY-002" ||
		f.Fingerprint == "" || f.Source != "rules" {
		t.Errorf("metadata incomplete: %+v", f)
	}
}

func TestPortOneSafe(t *testing.T) {
	fs, _, err := Evaluate("../../testdata/rules/KR-PAY-002/safe", []string{"fastapi"}, embedded(t), aidefensekit.Data)
	if err != nil || len(fs) != 0 {
		t.Fatalf("err=%v findings=%v", err, fs)
	}
}

func portOneTS(t *testing.T, sub string) []finding.Finding {
	t.Helper()
	fs, _, err := Evaluate("../../testdata/rules/KR-PAY-002/"+sub, []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestPortOneTSVulnerable(t *testing.T) {
	fs := portOneTS(t, "vulnerable")
	n := 0
	for _, f := range fs {
		if f.Location == "app/api/webhook/route.ts" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want 1 finding for route.ts, got %v", fs)
	}
}

func TestPortOneTSSafe(t *testing.T) {
	root := t.TempDir()
	src, err := os.ReadFile("../../testdata/rules/KR-PAY-002/safe/app/api/webhook/route.ts")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "app/api/webhook/route.ts", string(src))
	fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil || len(fs) != 0 {
		t.Fatalf("err=%v findings=%v", err, fs)
	}
}

// Review Focus 2: checkout code using the browser SDK is not a webhook receiver.
func TestPortOneBrowserCheckoutIgnored(t *testing.T) {
	root := t.TempDir()
	src, err := os.ReadFile("../../testdata/rules/KR-PAY-002/safe/app/checkout/page.tsx")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "app/checkout/page.tsx", string(src))
	fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil || len(fs) != 0 {
		t.Fatalf("err=%v findings=%v", err, fs)
	}
	// Control: the same file without the browser SDK import is a webhook-like suspect.
	write(t, root, "app/checkout/page.tsx", strings.ReplaceAll(string(src), "@portone/browser-sdk", "portone-x"))
	fs, _, err = Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil || len(fs) != 1 {
		t.Fatalf("control: want 1 finding once the marker is gone, got %v", fs)
	}
}

func TestPortOneRequeryIsSafe(t *testing.T) {
	root := t.TempDir()
	src, err := os.ReadFile("../../testdata/rules/KR-PAY-002/safe/app/webhook_requery.py")
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, "app/webhook_requery.py", string(src))
	fs, _, err := Evaluate(root, []string{"fastapi"}, embedded(t), aidefensekit.Data)
	if err != nil || len(fs) != 0 {
		t.Fatalf("err=%v findings=%v", err, fs)
	}
}

func TestStackFilter(t *testing.T) {
	rs := embedded(t)
	root := "../../testdata/rules/KR-PAY-002/vulnerable"
	// KR-PAY-002 applies to fastapi/nextjs; supabase only must not match.
	fs, _, _ := Evaluate(root, []string{"supabase"}, rs, aidefensekit.Data)
	if len(fs) != 0 {
		t.Fatalf("want 0, got %v", fs)
	}
	fs, _, _ = Evaluate(root, []string{"nextjs"}, rs, aidefensekit.Data)
	if len(fs) != 2 {
		t.Fatalf("overlap should apply, got %v", fs)
	}
}

func rulesFS(body string) fstest.MapFS {
	return fstest.MapFS{"rules/r.yaml": {Data: []byte(body)}}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func evalOne(t *testing.T, fsys fstest.MapFS, root string) []finding.Finding {
	t.Helper()
	rs, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	fs, _, err := Evaluate(root, nil, rs, fsys)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

const vulnRule = `id: T-1
title: t
severity: high
match:
  files: ["**/*.py"]
  has_any: ["portone"]
  missing_all: ["verify("]
`

func TestSkipsVendorAndBinary(t *testing.T) {
	root := t.TempDir()
	bad := "portone\n"
	for _, d := range []string{"node_modules", ".git", ".next", "dist", "build", "vendor", ".venv", "__pycache__", "sub/node_modules"} {
		write(t, root, d+"/x.py", bad)
	}
	write(t, root, "bin.py", "portone\x00\x01")
	write(t, root, "big.py", "portone\n"+strings.Repeat("a", 1<<20))
	if fs := evalOne(t, rulesFS(vulnRule), root); len(fs) != 0 {
		t.Fatalf("want 0, got %v", fs)
	}
	write(t, root, "ok.py", bad)
	if fs := evalOne(t, rulesFS(vulnRule), root); len(fs) != 1 || fs[0].Location != "ok.py" {
		t.Fatalf("control file not found: %v", fs)
	}
}

func TestFingerprintStableAcrossLineShift(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write(t, a, "w.py", "import portone\n")
	write(t, b, "w.py", strings.Repeat("\n", 10)+"import portone\n")
	fa, fb := evalOne(t, rulesFS(vulnRule), a), evalOne(t, rulesFS(vulnRule), b)
	if len(fa) != 1 || len(fb) != 1 {
		t.Fatal("expected one finding each")
	}
	if fa[0].Line == fb[0].Line || fa[0].Fingerprint != fb[0].Fingerprint {
		t.Errorf("lines %d/%d fp %s/%s", fa[0].Line, fb[0].Line, fa[0].Fingerprint, fb[0].Fingerprint)
	}
}

func TestRepoScope(t *testing.T) {
	rule := strings.Replace(vulnRule, "match:\n", "match:\n  scope: repo\n", 1)
	root := t.TempDir()
	write(t, root, "a.py", "portone\n")
	write(t, root, "b.py", "verify(x)\n")
	if fs := evalOne(t, rulesFS(rule), root); len(fs) != 0 {
		t.Fatalf("verify elsewhere should clear: %v", fs)
	}
	root2 := t.TempDir()
	write(t, root2, "z.py", "portone\n")
	write(t, root2, "a/y.py", "portone\n")
	fs := evalOne(t, rulesFS(rule), root2)
	if len(fs) != 1 || fs[0].Location != "a/y.py" {
		t.Fatalf("want one finding at first matched file, got %v", fs)
	}
}

func TestEvidenceTruncatedRuneSafe(t *testing.T) {
	root := t.TempDir()
	write(t, root, "w.py", "  portone "+strings.Repeat("가", 300)+"  \n")
	fs := evalOne(t, rulesFS(vulnRule), root)
	if len(fs) != 1 {
		t.Fatal(fs)
	}
	if n := len([]rune(fs[0].Evidence)); n != 200 {
		t.Errorf("evidence runes = %d", n)
	}
	if strings.HasPrefix(fs[0].Evidence, " ") {
		t.Error("not trimmed")
	}
}

func TestUnreadableFileWarns(t *testing.T) {
	root := t.TempDir()
	write(t, root, "ok.py", "portone\n")
	p := filepath.Join(root, "locked.py")
	write(t, root, "locked.py", "portone\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Skip()
	}
	if f, err := os.Open(p); err == nil { // running as root: cannot test
		f.Close()
		t.Skip("file readable despite chmod 0")
	}
	rs, _ := Load(rulesFS(vulnRule))
	fs, warns, err := Evaluate(root, nil, rs, rulesFS(vulnRule))
	if err != nil || len(fs) != 1 || len(warns) != 1 {
		t.Fatalf("err=%v fs=%v warns=%v", err, fs, warns)
	}
}

func TestSymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	write(t, real, "w.py", "portone\n")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unsupported")
	}
	fs := evalOne(t, rulesFS(vulnRule), link)
	if len(fs) != 1 || fs[0].Location != "w.py" {
		t.Fatalf("got %v", fs)
	}
}

func TestEvidenceMasksLongTokens(t *testing.T) {
	key := "Z8x2Kq9L" + "mN3vB7cX1pR5tY6uW0eA4sD2fG8hJ3kL" // 40 chars, test-only
	line := `resp = requests.post(url, headers={"Authorization": "PortOne ` + key + `"}) # portone`
	root := t.TempDir()
	write(t, root, "w.py", line+"\n")
	fs := evalOne(t, rulesFS(vulnRule), root)
	if len(fs) != 1 {
		t.Fatal(fs)
	}
	ev := fs[0].Evidence
	if strings.Contains(ev, key) || strings.Contains(ev, key[4:]) || strings.Contains(ev, key[:16]) {
		t.Errorf("evidence leaks key: %q", ev)
	}
	// 규칙은 주석 안의 portone에 걸렸지만 근거에는 주석이 나오지 않고 표시만 남는다.
	if !strings.Contains(ev, "****") || strings.Contains(ev, "portone") || !strings.Contains(ev, commentMarker) {
		t.Errorf("evidence = %q", ev)
	}
	// the fingerprint hashes the shown evidence, never the source line
	if want := finding.MakeMaskedFingerprint("T-1", "w.py", ev, 0); fs[0].Fingerprint != want {
		t.Errorf("fingerprint = %s, want %s", fs[0].Fingerprint, want)
	}
}

const regexRule = `id: T-2
title: t
severity: high
match:
  files: ["**/*.ts"]
  has_any_regex: ['createClient\(\s*"[^"]*"']
`

func TestHasAnyRegexMatches(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.ts", "const a = 1\nconst c = createClient(  \"https://x\")\n")
	write(t, root, "b.ts", "createClient(url)\n")
	fs := evalOne(t, rulesFS(regexRule), root)
	if len(fs) != 1 || fs[0].Location != "a.ts" || fs[0].Line != 2 {
		t.Fatalf("want one finding a.ts:2, got %v", fs)
	}
}

func TestMissingAllRegexSuppresses(t *testing.T) {
	rule := regexRule + "  missing_all_regex: ['auth\\.(get|verify)\\w*']\n"
	root := t.TempDir()
	write(t, root, "a.ts", "createClient(\"u\")\nauth.verifyUser()\n")
	write(t, root, "b.ts", "createClient(\"u\")\n")
	fs := evalOne(t, rulesFS(rule), root)
	if len(fs) != 1 || fs[0].Location != "b.ts" {
		t.Fatalf("want only b.ts, got %v", fs)
	}
}

func TestRequireAllGates(t *testing.T) {
	rule := `id: T-3
title: t
severity: high
match:
  files: ["**/*.tsx"]
  has_any: ["secret"]
  require_all: ["use client", "import"]
`
	root := t.TempDir()
	write(t, root, "no.tsx", "import x\nsecret\n")
	write(t, root, "yes.tsx", "'use client'\nimport x\nsecret\n")
	fs := evalOne(t, rulesFS(rule), root)
	if len(fs) != 1 || fs[0].Location != "yes.tsx" {
		t.Fatalf("want only yes.tsx, got %v", fs)
	}
}

func TestRequireAllRepoScopeSameFile(t *testing.T) {
	rule := `id: T-4
title: t
severity: high
match:
  scope: repo
  files: ["**/*.tsx"]
  has_any: ["secret"]
  require_all: ["use client"]
`
	root := t.TempDir()
	write(t, root, "a.tsx", "secret\n")
	write(t, root, "b.tsx", "'use client'\n")
	if fs := evalOne(t, rulesFS(rule), root); len(fs) != 0 {
		t.Fatalf("require_all must hold in the hit file, got %v", fs)
	}
	write(t, root, "c.tsx", "'use client'\nsecret\n")
	if fs := evalOne(t, rulesFS(rule), root); len(fs) != 1 || fs[0].Location != "c.tsx" {
		t.Fatalf("want c.tsx, got %v", fs)
	}
}

func TestRegexLineIsFirstMatch(t *testing.T) {
	rule := `id: T-5
title: t
severity: high
match:
  files: ["**/*.ts"]
  has_any: ["zzz"]
  has_any_regex: ['foo\d+']
`
	root := t.TempDir()
	write(t, root, "a.ts", "x\ny\nfoo12 bar\nzzz\nfoo9\n")
	fs := evalOne(t, rulesFS(rule), root)
	if len(fs) != 1 || fs[0].Line != 3 || fs[0].Evidence != "foo12 bar" {
		t.Fatalf("want line 3, got %v", fs)
	}
	write(t, root, "a.ts", "x\nzzz\nfoo12\n")
	fs = evalOne(t, rulesFS(rule), root)
	if len(fs) != 1 || fs[0].Line != 2 {
		t.Fatalf("earliest of both kinds should win, got %v", fs)
	}
}

// authFindings runs the embedded rules over a folder and returns the findings
// of one rule, keyed by file path.
func authFindings(t *testing.T, root, id string) map[string]int {
	t.Helper()
	fs, _, err := Evaluate(root, []string{"nextjs", "fastapi"}, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range fs {
		if f.ID == id {
			got[f.Location]++
		}
	}
	return got
}

// oauthCases runs the same three scenarios for Kakao and Naver.
func oauthCases(t *testing.T, id, authURL string) {
	dir := "../../testdata/rules/" + id
	t.Run("missing", func(t *testing.T) {
		got := authFindings(t, dir+"/vulnerable", id)
		if got["app/login.ts"] != 1 || got["app/login.py"] != 1 {
			t.Fatalf("want one finding each for login.ts and login.py, got %v", got)
		}
	})
	t.Run("present", func(t *testing.T) {
		if got := authFindings(t, dir+"/safe", id); len(got) != 0 {
			t.Fatalf("want no findings, got %v", got)
		}
	})
	t.Run("useState is not state", func(t *testing.T) {
		got := authFindings(t, dir+"/vulnerable", id)
		if got["app/LoginButton.tsx"] != 1 {
			t.Fatalf("want one finding for LoginButton.tsx, got %v", got)
		}
	})
	// Each of these must NOT count as an OAuth state parameter.
	for name, body := range map[string]string{
		"useState":        `const [v, setV] = useState("a")`,
		"setState":        `setState({ a: 1 })`,
		"this.state":      `this.state = { a: 1 }`,
		"this.state read": `const s = this.state.count`,
		"state.foo":       `const x = state.foo`,
		"destructure":     `const [state, setState] = useState(0)`,
		"comparison":      `if (state == 1) {}`,
	} {
		t.Run("not state/"+name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "a.ts", "fetch(\"https://"+authURL+"?client_id=x\")\n"+body+"\n")
			if got := authFindings(t, root, id); got["a.ts"] != 1 {
				t.Fatalf("want 1 finding, got %v", got)
			}
		})
	}
	// Each of these IS an OAuth state parameter.
	for name, body := range map[string]string{
		"&state=":          `const u = "` + authURL + `?a=1&state=" + csrf`,
		"?state=":          `const u = "` + authURL + `?state=" + csrf`,
		"state: value":     `const p = { state: csrf }`,
		"quoted key":       `const p = { "state": csrf }`,
		"single quoted":    `const p = { 'state' : csrf }`,
		"python kwarg":     `build(client_id=cid, state=csrf)`,
		"python dict":      `params = {"state": csrf}`,
		"searchParams.set": `url.searchParams.set("state", csrf)`,
		"spaced equals":    `state = csrf`,
	} {
		t.Run("is state/"+name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, "a.ts", "fetch(\""+authURL+"\")\n"+body+"\n")
			if got := authFindings(t, root, id); len(got) != 0 {
				t.Fatalf("want no findings, got %v", got)
			}
		})
	}
	t.Run("other files ignored", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, "a.ts", "const x = 1\n")
		if got := authFindings(t, root, id); len(got) != 0 {
			t.Fatalf("want no findings, got %v", got)
		}
	})
}

func TestKakaoState(t *testing.T) { oauthCases(t, "KR-AUTH-001", "kauth.kakao.com/oauth/authorize") }

func TestNaverState(t *testing.T) { oauthCases(t, "KR-AUTH-002", "nid.naver.com/oauth2.0/authorize") }

func TestAuthRuleMetadata(t *testing.T) {
	for id, want := range map[string]finding.Confidence{"KR-AUTH-001": finding.Suspect, "KR-AUTH-002": finding.Suspect} {
		fs, _, err := Evaluate("../../testdata/rules/"+id+"/vulnerable", []string{"nextjs"}, embedded(t), aidefensekit.Data)
		if err != nil || len(fs) == 0 {
			t.Fatalf("%s: err=%v findings=%v", id, err, fs)
		}
		f := fs[0]
		if f.ID != id || f.Severity != finding.Medium || f.Confidence != want || f.ExplainKo == "" || f.Fix == "" || len(f.References) == 0 {
			t.Errorf("%s: unexpected finding %+v", id, f)
		}
	}
}

func tossFindings(t *testing.T, sub string) map[string]int {
	t.Helper()
	got := map[string]int{}
	for loc, ids := range tossRuleIDs(t, sub) {
		for _, id := range ids {
			if id == "KR-PAY-001" {
				got[loc]++
			}
		}
	}
	return got
}

// tossRuleIDs returns every rule ID (all rules, not only KR-PAY-001) per file.
func tossRuleIDs(t *testing.T, sub string) map[string][]string {
	t.Helper()
	fs, _, err := Evaluate("../../testdata/rules/KR-PAY-001/"+sub, []string{"fastapi", "nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range fs {
		got[f.Location] = append(got[f.Location], f.ID)
	}
	return got
}

func TestTossWebhookVulnerable(t *testing.T) {
	got := tossFindings(t, "vulnerable")
	for _, loc := range []string{"app/toss_webhook.py", "app/api/toss/webhook/route.ts", "app/api/toss/deposit/route.ts", "app/toss_vbank.py", "app/api/toss/vbank/route.ts", "app/toss_vbank_snake.py", "app/express_vbank.js"} {
		if got[loc] != 1 {
			t.Errorf("%s: want 1 finding, got %d (all: %v)", loc, got[loc], got)
		}
	}
}

func TestTossWebhookSafe(t *testing.T) {
	if got := tossRuleIDs(t, "safe"); len(got) != 0 {
		t.Fatalf("safe fixtures flagged by some rule: %v", got)
	}
}

// 가상계좌 입금 웹훅은 본문에 eventType이 없어 "DEPOSIT_CALLBACK" 문자열이 없을 수 있다.
// 본문 모양(transactionKey + secret)으로 찾고, 안전한 파일은 건드리지 않는다.
func TestTossDepositBodyShape(t *testing.T) {
	vuln := tossFindings(t, "vulnerable")
	for _, loc := range []string{"app/toss_vbank.py", "app/api/toss/vbank/route.ts", "app/toss_vbank_snake.py", "app/express_vbank.js"} {
		if vuln[loc] != 1 {
			t.Errorf("%s: want 1 finding, got %d", loc, vuln[loc])
		}
	}
	safe := tossRuleIDs(t, "safe")
	for _, loc := range []string{"app/toss_vbank_checked.py", "app/toss_confirm_caller.py", "app/toss_secret_only.py", "app/toss_confirm_helper.py", "app/schema.ts", "app/models.py"} {
		if ids := safe[loc]; len(ids) != 0 {
			t.Errorf("%s: want no findings, got %v", loc, ids)
		}
	}
}

func TestTossDepositShapeBoundaries(t *testing.T) {
	cases := map[string]bool{
		"x = request.json()\nk = lastTransactionKey\ns = body['secret']\n":      false,
		"x = request.json()\nk = body['transactionKey']\ns = body['secret']\n":  true,
		"s = body['secret']\nk = body['transaction_key']\nx = request.json()\n": true,
		"k = body['transactionKey']\ns = body['secret']\n":                      false,
	}
	for src, flagged := range cases {
		root := t.TempDir()
		write(t, root, "a.py", src)
		fs, _, err := Evaluate(root, []string{"fastapi"}, embedded(t), aidefensekit.Data)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range fs {
			if f.ID == "KR-PAY-001" {
				n++
			}
		}
		if (n == 1) != flagged {
			t.Errorf("%q: flagged=%v want %v", src, n == 1, flagged)
		}
	}
}

func TestTossVulnerableOnlyTossRule(t *testing.T) {
	for loc, ids := range tossRuleIDs(t, "vulnerable") {
		if len(ids) != 1 || ids[0] != "KR-PAY-001" {
			t.Errorf("%s: want exactly [KR-PAY-001], got %v", loc, ids)
		}
	}
}

func TestPortOneSignatureHeaderBoundary(t *testing.T) {
	count := func(name, src string) int {
		root := t.TempDir()
		write(t, root, name, src)
		fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range fs {
			if f.ID == "KR-PAY-002" {
				n++
			}
		}
		return n
	}
	if n := count("a.ts", "const sig = req.headers.get(\"tosspayments-webhook-signature\");\n"); n != 0 {
		t.Errorf("Toss header triggered KR-PAY-002 %d times", n)
	}
	if n := count("b.ts", "const sig = req.headers.get(\"webhook-signature\");\n"); n != 1 {
		t.Errorf("bare webhook-signature: want 1 KR-PAY-002, got %d", n)
	}
	if n := count("d.ts", "const k = \"x_webhook-signature\";\n"); n != 0 {
		t.Errorf("word char before: want 0, got %d", n)
	}
	if n := count("e.ts", "const k = req.headers.get(\"acme-webhook-signature\");\n"); n != 0 {
		t.Errorf("other vendor header (deliberately not matched): want 0, got %d", n)
	}
	if n := count("c.ts", "webhook-signature: x\n"); n != 1 {
		t.Errorf("line-start webhook-signature: want 1, got %d", n)
	}
}

func TestTossSecretComparisonVariants(t *testing.T) {
	cases := map[string]bool{
		"if (body.secret !== saved) return;":       false,
		"if saved == body.secret:":                 false,
		"hmac.compare_digest(body[\"secret\"], s)": false,
		"const s = body.secret;":                   true,
		"const secretKey = a === b;":               true,
		"x = data[\"secret\"]":                     true,
	}
	// Known limits (documented in the rule): an unrelated comparison on the
	// same line as `secret` also suppresses the finding.
	cases[`if (body.eventType === "DEPOSIT_CALLBACK") { const secret = body.secret; markPaid(); }`] = false
	cases[`const ok = !!body.secret && body.status === "DONE";`] = false
	for line, flagged := range cases {
		root := t.TempDir()
		write(t, root, "a.ts", "// DEPOSIT_CALLBACK\n"+line+"\n")
		fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range fs {
			if f.ID == "KR-PAY-001" {
				n++
			}
		}
		if (n == 1) != flagged {
			t.Errorf("%q: flagged=%v want %v", line, n == 1, flagged)
		}
	}
}

func TestTossRuleMetadata(t *testing.T) {
	fs, _, err := Evaluate("../../testdata/rules/KR-PAY-001/vulnerable", []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil || len(fs) == 0 {
		t.Fatalf("err=%v findings=%v", err, fs)
	}
	f := fs[0]
	if f.ID != "KR-PAY-001" || f.Severity != finding.High || f.Confidence != finding.Suspect || f.ExplainKo == "" || f.Fix == "" || len(f.References) != 5 {
		t.Errorf("unexpected finding %+v", f)
	}
}

func sbFindings(t *testing.T, root, id string) map[string][]finding.Finding {
	t.Helper()
	fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]finding.Finding{}
	for _, f := range fs {
		if f.ID == id {
			got[f.Location] = append(got[f.Location], f)
		}
	}
	return got
}

func TestSB002EnvFile(t *testing.T) {
	got := sbFindings(t, "../../testdata/rules/SB-002/vulnerable", "SB-002")
	for _, p := range []string{".env.local", "web/.env.production", ".env.example"} {
		if len(got[p]) != 1 {
			t.Errorf("%s: want 1 finding, got %v (all: %v)", p, got[p], got)
		}
	}
	f := got[".env.local"][0]
	if f.Line != 2 || f.Severity != finding.Critical || f.Confidence != finding.Certain || f.ExplainKo == "" || f.Fix == "" || len(f.References) == 0 {
		t.Errorf("unexpected finding %+v", f)
	}
}

func TestSB002Safe(t *testing.T) {
	if got := sbFindings(t, "../../testdata/rules/SB-002/safe", "SB-002"); len(got) != 0 {
		t.Fatalf("want none, got %v", got)
	}
}

// Dotfiles must be matched by the rule's own file patterns.
func TestSB002FilePatternsMatchDotEnv(t *testing.T) {
	var r Rule
	for _, x := range embedded(t) {
		if x.ID == "SB-002" {
			r = x
		}
	}
	if r.ID == "" {
		t.Fatal("SB-002 not loaded")
	}
	for _, p := range []string{".env", ".env.local", "web/.env.local", "a/b/.env.production"} {
		if !matchesFiles(r, p) {
			t.Errorf("%s not matched", p)
		}
	}
	// I1: code and config files are scanned, documentation is not.
	for _, p := range []string{"app/page.tsx", "lib/a.js", "src/x.jsx", "a.ts", "b.mjs", "c.cjs", "next.config.js", "web/next.config.mjs"} {
		if !matchesFiles(r, p) {
			t.Errorf("%s not matched", p)
		}
	}
	for _, p := range []string{"README.md", "AGENTS.md", "docs/setup.md", "notes.txt"} {
		if matchesFiles(r, p) {
			t.Errorf("%s matched, want skipped", p)
		}
	}
}

func TestSB002NameRegex(t *testing.T) {
	cases := map[string]bool{
		"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x": true,
		"NEXT_PUBLIC_SUPABASE_SECRET_KEY=x":       true,
		"NEXT_PUBLIC_SERVICE_ROLE_KEY=x":          true,
		"NEXT_PUBLIC_STRIPE_SECRET_KEY=x":         true,
		"NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=x":  false,
		"NEXT_PUBLIC_SUPABASE_ANON_KEY=x":         false,
		"NEXT_PUBLIC_RECAPTCHA_SITE_KEY=x":        false,
		"SUPABASE_SECRET_KEY=x":                   false,
		"SUPABASE_SERVICE_ROLE_KEY=x":             false,
	}
	for line, want := range cases {
		root := t.TempDir()
		write(t, root, ".env.local", line+"\n")
		fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range fs {
			if f.ID == "SB-002" {
				n++
			}
		}
		if (n == 1) != want || n > 1 {
			t.Errorf("%q: findings=%d want match=%v", line, n, want)
		}
	}
}

func TestSB002EvidenceMasksValue(t *testing.T) {
	val := "Q7w3Er5Ty9Ui1Op2As4Df6Gh8Jk0Lz3Xc5Vb7Nm9" // 40 chars, test-only
	root := t.TempDir()
	write(t, root, ".env.local", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY="+val+"\n")
	got := sbFindings(t, root, "SB-002")
	if len(got[".env.local"]) != 1 {
		t.Fatal(got)
	}
	ev := got[".env.local"][0].Evidence
	if strings.Contains(ev, val) || strings.Contains(ev, val[:16]) || strings.Contains(ev, val[4:]) {
		t.Errorf("evidence leaks value: %q", ev)
	}
	if !strings.Contains(ev, "****") {
		t.Errorf("evidence not masked: %q", ev)
	}
}

func TestSB003UseClient(t *testing.T) {
	got := sbFindings(t, "../../testdata/rules/SB-003/vulnerable", "SB-003")
	if len(got["app/admin.tsx"]) != 1 || len(got["lib/admin.js"]) != 1 || len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	f := got["app/admin.tsx"][0]
	if f.Line != 8 || f.Severity != finding.High || f.Confidence != finding.Suspect || f.ExplainKo == "" || f.Fix == "" || len(f.References) == 0 {
		t.Errorf("unexpected finding %+v", f)
	}
}

func TestSB003ServerFileSafe(t *testing.T) {
	if got := sbFindings(t, "../../testdata/rules/SB-003/safe", "SB-003"); len(got) != 0 {
		t.Fatalf("want none (route.ts has no use client; page.tsx uses publishable key), got %v", got)
	}
}

// C1/I2: evidence on the sample app names the identifier or address that fired
// and never prints the raw value.
func TestSampleAppEvidence(t *testing.T) {
	fs, _, err := Evaluate("../../testdata/e2e/sample-app", []string{"nextjs", "fastapi"}, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"SB-002":      "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=****",
		"SB-003":      "process.env.SUPABASE_SERVICE_ROLE_KEY!,",
		"KR-AUTH-001": "return `https://kauth.kakao.com/oauth/authorize?response_type=****&client_id=${clientId}&redirect_uri=${redirect}`;",
		"KR-PAY-002":  `@router.post("/webhook/portone")`,
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.ID] = f.Evidence
	}
	for id, ev := range want {
		if got[id] != ev {
			t.Errorf("%s evidence = %q, want %q", id, got[id], ev)
		}
	}
}

// C1 probe: a short value in an env file is masked while the name stays.
func TestSB002ShortValueMasked(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env.local", `NEXT_PUBLIC_JWT_SECRET="mysecret123"`+"\n")
	fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Evidence != `NEXT_PUBLIC_JWT_SECRET=****` {
		t.Fatalf("got %+v", fs)
	}
}

// End to end: short values in typed or fallback assignments never
// reach evidence, and the rule's identifier stays visible.
func TestRuleEvidenceNoShortValues(t *testing.T) {
	cases := []struct{ file, content, id, raw, keep string }{
		{"a.ts", `const NEXT_PUBLIC_JWT_SECRET: string = "abc123";`, "SB-002", "abc123", "NEXT_PUBLIC_JWT_SECRET"},
		{"b.ts", `const s = process.env.NEXT_PUBLIC_JWT_SECRET || "mysecret123";`, "SB-002", "mysecret123", "process.env.NEXT_PUBLIC_JWT_SECRET"},
		{"c.ts", "const NEXT_PUBLIC_JWT_SECRET = `abc123`;", "SB-002", "abc123", "NEXT_PUBLIC_JWT_SECRET"},
		{"d.tsx", "'use client'\nconst SUPABASE_SERVICE_ROLE_KEY: string = \"abc123\";", "SB-003", "abc123", "SUPABASE_SERVICE_ROLE_KEY"},
		{"e.ts", `const portoneKey: string = "pk123";`, "KR-PAY-002", "pk123", "portoneKey"},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, c.file, c.content+"\n")
		fs, _, err := Evaluate(root, []string{"nextjs"}, embedded(t), aidefensekit.Data)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, f := range fs {
			if f.ID != c.id {
				continue
			}
			n++
			if strings.Contains(f.Evidence, c.raw) || !strings.Contains(f.Evidence, c.keep) {
				t.Errorf("%s %s: evidence %q", c.id, c.file, f.Evidence)
			}
		}
		if n != 1 {
			t.Errorf("%s %s: %d findings", c.id, c.file, n)
		}
	}
}

// allFindings runs every embedded rule for the given stacks and groups by file.
func allFindings(t *testing.T, root string, stacks []string) map[string][]finding.Finding {
	t.Helper()
	fs, _, err := Evaluate(root, stacks, embedded(t), aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]finding.Finding{}
	for _, f := range fs {
		got[f.Location] = append(got[f.Location], f)
	}
	return got
}

func TestFA001Vulnerable(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/FA-001/vulnerable", []string{"fastapi"})
	for _, p := range []string{"multiline/main.py", "single/main.py", "reversed/main.py", "spaced/main.py"} {
		fs := got[p]
		if len(fs) != 1 || fs[0].ID != "FA-001" {
			t.Errorf("%s: want exactly 1 FA-001 finding, got %+v", p, fs)
			continue
		}
		f := fs[0]
		if f.Severity != finding.High || f.ExplainKo == "" || f.Fix == "" || len(f.References) == 0 {
			t.Errorf("%s: unexpected finding %+v", p, f)
		}
	}
	if len(got) != 4 {
		t.Errorf("want findings in 4 files only, got %v", got)
	}
}

// safeStacks turns on every stack the plan-3 rules use, so "no finding from
// any rule" also covers the other stacks' rules.
var safeStacks = []string{"fastapi", "nextjs", "supabase"}

func TestFA001Safe(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/FA-001/safe", safeStacks); len(got) != 0 {
		t.Fatalf("want no findings from any rule, got %v", got)
	}
}

func TestFA001RegexBoundaries(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
	}{
		{"trailing comma", "app.add_middleware(CORSMiddleware, allow_origins=[\"*\",], allow_credentials=True,)", 1},
		{"star among others", "app.add_middleware(CORSMiddleware, allow_origins=[\"https://a.example\", \"*\"], allow_credentials=True)", 1},
		{"subdomain wildcard", "app.add_middleware(CORSMiddleware, allow_origins=[\"*.example.com\"], allow_credentials=True)", 0},
		{"scheme wildcard", "app.add_middleware(CORSMiddleware, allow_origins=[\"https://*\"], allow_credentials=True)", 0},
		{"credentials false", "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False)", 0},
		{"no CORSMiddleware", "x = dict(allow_origins=['*'], allow_credentials=True)", 0},
		{"allow_origin_regex (known miss)", "app.add_middleware(CORSMiddleware, allow_origin_regex=\".*\", allow_credentials=True)", 0},
		{"commented-out star (known false positive)", "# allow_origins=[\"*\"]\napp.add_middleware(CORSMiddleware, allow_origins=[\"https://a.example\"], allow_credentials=True)", 1},
		{"two calls in one file (known false positive)", "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"])\napp.add_middleware(CORSMiddleware, allow_origins=[\"https://a.example\"], allow_credentials=True)", 1},
		{"Middleware list form", "middleware = [Middleware(CORSMiddleware, allow_origins=[\"*\"], allow_credentials=True)]", 1},
		{"variable (known miss)", "origins = ['*']\napp.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True)", 0},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, "main.py", c.body+"\n")
		n := 0
		for _, f := range allFindings(t, root, []string{"fastapi"})["main.py"] {
			if f.ID == "FA-001" {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, n)
		}
	}
}

func TestFA001StackFilter(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/FA-001/vulnerable", []string{"nextjs"}); len(got) != 0 {
		t.Fatalf("FA-001 must not run without the fastapi stack: %v", got)
	}
}

func TestFA002Exposed(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/FA-002/vulnerable", []string{"fastapi"})
	for _, p := range []string{"plain/main.py", "with_title/main.py"} {
		fs := got[p]
		if len(fs) != 1 || fs[0].ID != "FA-002" {
			t.Errorf("%s: want exactly 1 FA-002 finding, got %+v", p, fs)
			continue
		}
		f := fs[0]
		if f.Severity != finding.Low || f.ExplainKo == "" || f.Fix == "" || len(f.References) == 0 {
			t.Errorf("%s: unexpected finding %+v", p, f)
		}
	}
	if len(got) != 2 {
		t.Errorf("want findings in 2 files only, got %v", got)
	}
}

func TestFA002Disabled(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/FA-002/safe", safeStacks); len(got) != 0 {
		t.Fatalf("want no findings from any rule, got %v", got)
	}
}

func TestFA002RegexBoundaries(t *testing.T) {
	cases := []struct {
		name, body string
		want       int
	}{
		{"plain", "app = FastAPI()", 1},
		{"with args", "app = FastAPI(title=\"x\")", 1},
		{"module attribute", "app = fastapi.FastAPI()", 1},
		{"docs_url none", "app = FastAPI(docs_url=None, redoc_url=None)", 0},
		{"docs_url none spaced", "app = FastAPI(docs_url = None)", 0},
		{"openapi_url none", "app = FastAPI(openapi_url=None)", 0},
		{"openapi_url setting", "app = FastAPI(openapi_url=settings.openapi_url)", 0},
		{"openapi_url literal path (still exposed)", "app = FastAPI(openapi_url=\"/api/openapi.json\")", 1},
		{"import only", "from fastapi import FastAPI", 0},
		{"APIRouter", "router = APIRouter()", 0},
		{"subclass (known miss)", "class App(FastAPI):\n    pass\nx = App()", 0},
		{"commented out", "# app = FastAPI()", 0},
		{"two apps, one disabled (known miss)", "a = FastAPI(docs_url=None)\nb = FastAPI()", 0},
		{"two apps both exposed", "a = FastAPI()\nb = FastAPI()", 1},
		{"other class name", "app = MyFastAPI()", 0},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, "main.py", c.body+"\n")
		n := 0
		for _, f := range allFindings(t, root, []string{"fastapi"})["main.py"] {
			if f.ID == "FA-002" {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, n)
		}
	}
}

func TestFA002StackFilter(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/FA-002/vulnerable", []string{"nextjs"}); len(got) != 0 {
		t.Fatalf("FA-002 must not run without the fastapi stack: %v", got)
	}
}

func TestNX001AuthInMiddleware(t *testing.T) {
	for sub, loc := range map[string]string{"root_middleware": "middleware.ts", "src_proxy": "src/proxy.ts"} {
		got := allFindings(t, "../../testdata/rules/NX-001/vulnerable/"+sub, []string{"nextjs"})
		fs := got[loc]
		if len(fs) != 1 || fs[0].ID != "NX-001" {
			t.Errorf("%s: want exactly 1 NX-001 finding, got %+v", loc, fs)
			continue
		}
		f := fs[0]
		if f.Severity != finding.Low || f.ExplainKo == "" || f.Fix == "" || len(f.References) == 0 {
			t.Errorf("%s: unexpected finding %+v", loc, f)
		}
		if len(got) != 1 {
			t.Errorf("%s: want findings in 1 file only, got %v", sub, got)
		}
	}
}

func TestNX001NonAuthMiddleware(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/NX-001/safe/locale", safeStacks); len(got) != 0 {
		t.Fatalf("locale-only middleware must not match: %v", got)
	}
}

func TestNX001OtherFilesIgnored(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/NX-001/safe/other", safeStacks); len(got) != 0 {
		t.Fatalf("cookies() in app/page.tsx must not match: %v", got)
	}
}

func TestNX001FilesAndSignals(t *testing.T) {
	const authBody = "export function middleware(r) { return r.headers.get('Authorization') }\n"
	cases := []struct {
		name, path, body string
		want             int
	}{
		{"root middleware.ts", "middleware.ts", authBody, 1},
		{"root middleware.js", "middleware.js", authBody, 1},
		{"root proxy.ts", "proxy.ts", authBody, 1},
		{"root proxy.js", "proxy.js", authBody, 1},
		{"src middleware.ts", "src/middleware.ts", authBody, 1},
		{"src middleware.js", "src/middleware.js", authBody, 1},
		{"src proxy.ts", "src/proxy.ts", authBody, 1},
		{"src proxy.js", "src/proxy.js", authBody, 1},
		{"nested app dir not covered", "app/middleware.ts", authBody, 0},
		{"mjs not covered", "middleware.mjs", authBody, 0},
		{"authorization lowercase", "middleware.ts", "r.headers.get('authorization')", 1},
		{"getToken", "middleware.ts", "const t = await getToken({ req })", 1},
		{"auth call", "middleware.ts", "const s = await auth()", 1},
		{"session word", "middleware.ts", "const s = getSession(r)", 1},
		{"login path", "middleware.ts", "NextResponse.redirect('/login')", 1},
		{"cookies", "middleware.ts", "r.cookies.get('a')", 1},
		{"plain next", "middleware.ts", "return NextResponse.next()", 0},
		{"oauth word not auth call", "middleware.ts", "const x = oauth(1)", 0},
		{"author word", "middleware.ts", "// author: kim", 0},
		{"locale cookie (known false positive)", "middleware.ts", "const l = request.cookies.get('NEXT_LOCALE')?.value", 1},
		{"authjs re-export", "middleware.ts", "export { auth as middleware } from \"@/auth\"", 1},
		{"next-auth middleware", "middleware.ts", "export { default } from \"next-auth/middleware\"", 1},
		{"withAuth", "middleware.ts", "export default withAuth(function mw() {})", 1},
		{"clerkMiddleware", "middleware.ts", "export default clerkMiddleware()", 1},
		{"auth.protect", "middleware.ts", "await x.protect()", 1},
		{"security headers only", "middleware.ts", "res.headers.set('Content-Security-Policy', \"default-src 'self'\"); res.headers.set('x-frame-options', 'DENY')", 0},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, c.path, c.body)
		n := 0
		for _, f := range allFindings(t, root, []string{"nextjs"})[c.path] {
			if f.ID == "NX-001" {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, n)
		}
	}
}

func TestNX001StackFilter(t *testing.T) {
	if got := allFindings(t, "../../testdata/rules/NX-001/vulnerable/root_middleware", []string{"fastapi"}); len(got) != 0 {
		t.Fatalf("NX-001 must not run without the nextjs stack: %v", got)
	}
}
