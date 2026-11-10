package rules

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// The dangerous PHP shapes these rules look for also look like web shells to
// antivirus software, so they are built in memory here and never stored as
// files. A file in the repository could get it quarantined on a contributor's
// computer or a CI runner.
func phpLine(fn, input string) string { return fn + "(" + input + "['x']);" }

func phpRule(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range embedded(t) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no rule %s", id)
	return Rule{}
}

func phpHits(t *testing.T, id, line string) []finding.Finding {
	t.Helper()
	return lineFindings(phpRule(t, id), "a.php", "<?php\n"+line+"\n", []string{"php"}, aidefensekit.Data)
}

func TestPHPRulesFindDirectInput(t *testing.T) {
	const get, post, req, cookie = "$_GET", "$_POST", "$_REQUEST", "$_COOKIE"
	cases := []struct {
		id   string
		sev  finding.Severity
		conf finding.Confidence
		line string
	}{
		{"PH-001", finding.Critical, finding.Certain, phpLine("ev"+"al", post)},
		{"PH-001", finding.Critical, finding.Certain, phpLine("sys"+"tem", get)},
		{"PH-001", finding.Critical, finding.Certain, phpLine("SHELL_"+"EXEC", req)},
		{"PH-001", finding.Critical, finding.Certain, phpLine("pass"+"thru", cookie)},
		{"PH-002", finding.Critical, finding.Certain, phpLine("inc"+"lude", get)},
		{"PH-002", finding.Critical, finding.Certain, "require_once 'pages/' . " + req + "['p'] . '.php';"},
		{"PH-003", finding.High, finding.Suspect, `mysqli_query($db, "SELECT * FROM u WHERE id = " . ` + get + `['id']);`},
		{"PH-003", finding.High, finding.Suspect, `$sql = "DELETE FROM p WHERE id = ` + post + `[id]";`},
		{"PH-003", finding.High, finding.Suspect, `$pdo->query("SELECT * FROM a WHERE b = '" . ` + req + `['b'] . "'");`},
		{"PH-004", finding.High, finding.Certain, phpLine("unserial"+"ize", cookie)},
		{"PH-004", finding.High, finding.Certain, "$p = unserial" + "ize(base64_decode(" + post + "['d']));"},
		{"PH-005", finding.High, finding.Suspect, `move_uploaded_file($_FILES['f']['tmp_name'], "up/" . $_FILES['f']['name']);`},
		{"PH-005", finding.High, finding.Suspect, `move_uploaded_file($_FILES['g']['tmp_name'], 'up/' . basename($_FILES["g"]["name"]));`},
	}
	for _, c := range cases {
		t.Run(c.id+" "+c.line, func(t *testing.T) {
			got := phpHits(t, c.id, c.line)
			if len(got) != 1 {
				t.Fatalf("findings = %d", len(got))
			}
			f := got[0]
			if f.Line != 2 || f.Severity != c.sev || f.Confidence != c.conf {
				t.Errorf("line %d, %v, %v", f.Line, f.Severity, f.Confidence)
			}
			if f.ExplainKo == "" || !strings.HasPrefix(f.Fix, "# PHP") {
				t.Errorf("explain or fix missing: %.40q", f.Fix)
			}
		})
	}
}

func TestPHPRulesLeaveSafeLinesAlone(t *testing.T) {
	const get, post = "$_GET", "$_POST"
	cases := []struct{ id, line string }{
		{"PH-001", "// " + phpLine("ev"+"al", post)},
		{"PH-001", "# " + phpLine("sys"+"tem", get)},
		{"PH-001", "  * " + phpLine("sys"+"tem", get)},
		{"PH-001", `sys` + `tem("ls " . escapeshellarg(` + get + `['d']));`},
		{"PH-001", `$pdo->exec("SET NAMES utf8");`},
		{"PH-001", `$x->exec(` + get + `['q']);`},
		{"PH-001", `$medieval = ` + get + `['x'];`},
		{"PH-001", "ev" + "al($trusted);"},
		{"PH-001", "echo " + get + "['x'];"},
		{"PH-002", "include 'header.php';"},
		{"PH-002", "require_once __DIR__ . '/lib.php';"},
		{"PH-002", "include 'a.php'; echo " + get + "['x'];"},
		{"PH-003", `$st = $pdo->prepare("SELECT * FROM u WHERE id = ?"); $st->execute([` + get + `['id']]);`},
		{"PH-003", `mysqli_query($db, "SELECT * FROM u WHERE id = " . intval(` + get + `['id']));`},
		{"PH-003", `mysqli_query($db, "SELECT * FROM u WHERE id = " . (int) ` + get + `['id']);`},
		{"PH-003", `mysqli_query($db, "SELECT * FROM a WHERE b = '" . mysqli_real_escape_string($db, ` + get + `['b']) . "'");`},
		{"PH-003", `echo "please select one"; echo ` + get + `['x'];`},
		{"PH-003", `// mysqli_query($db, "SELECT " . ` + get + `['id']);`},
		{"PH-004", "$o = json_decode(" + post + "['c'], true);"},
		{"PH-004", "$p = unserial" + "ize($stored);"},
		{"PH-005", `move_uploaded_file($_FILES['f']['tmp_name'], "up/" . bin2hex(random_bytes(16)) . ".jpg");`},
		{"PH-005", `$n = $_FILES['f']['name'];`},
	}
	for _, c := range cases {
		if got := phpHits(t, c.id, c.line); len(got) != 0 {
			t.Errorf("%s flagged %q", c.id, c.line)
		}
	}
}

func TestPHPRuleStacksAndFiles(t *testing.T) {
	if r := phpRule(t, "PH-001"); !appliesTo(r, []string{"php"}) || appliesTo(r, []string{"nextjs"}) {
		t.Errorf("stacks = %v", r.Stacks)
	}
	if r := phpRule(t, "PH-001"); !matchesFiles(r, "public/a.php") || !matchesFiles(r, "views/a.phtml") || matchesFiles(r, "a.js") {
		t.Errorf("files = %v", r.Match.Files)
	}
}

// Only SQL and upload shapes live in files; the code execution shapes stay in memory.
func TestPHPRulesThroughEvaluate(t *testing.T) {
	cases := []struct{ id, name string }{{"PH-003", "query.php"}, {"PH-005", "upload.php"}}
	for _, c := range cases {
		got := allFindings(t, "../../testdata/rules/php/"+c.id+"/vulnerable", []string{"php"})
		if !hasID(got[c.name], c.id) {
			t.Errorf("%s: no finding in %s: %+v", c.id, c.name, got)
			continue
		}
		if got[c.name][0].Line != 3 {
			t.Errorf("%s: line = %d", c.id, got[c.name][0].Line)
		}
		if other := allFindings(t, "../../testdata/rules/php/"+c.id+"/vulnerable", []string{"nextjs"}); hasID(other[c.name], c.id) {
			t.Errorf("%s: applied without the php stack", c.id)
		}
		for l, fs := range allFindings(t, "../../testdata/rules/php/"+c.id+"/safe", []string{"php"}) {
			if hasID(fs, c.id) {
				t.Errorf("%s: safe example %s was flagged", c.id, l)
			}
		}
	}
}

// These are variables, not constants, so the compiler can't join a whole
// dangerous shape into one string in the test binary either.
var (
	phpGet    = "$_GET"
	phpPost   = "$_POST"
	phpEval   = "ev" + "al"
	phpSystem = "sys" + "tem"
	phpShell  = "shell_" + "exec"
	phpExec   = "ex" + "ec"
	phpAssert = "as" + "sert"
	phpIn     = phpGet + "['x']"
)

func phpCall(fn, args string) string { return fn + "(" + args + ")" }

func checkPHPCases(t *testing.T, id string, wantHit bool, lines []string) {
	t.Helper()
	for _, l := range lines {
		if got := phpHits(t, id, l); (len(got) == 1) != wantHit {
			t.Errorf("%s: findings = %d for %q", id, len(got), l)
		}
	}
}

func TestPH001Precision(t *testing.T) {
	checkPHPCases(t, "PH-001", false, []string{
		"<td>Operating " + phpSystem + " (<?= " + phpIn + " ?>)</td>",
		"if (" + phpCall(phpSystem, "$cmd") + " === 0 && isset(" + phpIn + ")) {",
		"public function " + phpExec + "($c) { return $this->run(" + phpIn + "); }",
		"$pdo-> " + phpCall(phpExec, phpIn) + ";",
		"$x = 1; // " + phpCall(phpSystem, phpIn),
		"<?php // " + phpCall(phpSystem, phpIn) + ";",
		phpCall(phpAssert, phpIn) + ";",
		phpCall(phpSystem, "$_get['x']") + ";",
	})
}

func TestPH001Recall(t *testing.T) {
	checkPHPCases(t, "PH-001", true, []string{
		phpCall(phpSystem, `"cd /tmp; ls " . `+phpIn) + ";",
		phpCall(phpSystem, `"c " . escapeshellarg($a) . " " . `+phpIn) + ";",
		phpCall(phpSystem, "foo($a) . "+phpIn) + ";",
		phpCall(phpSystem, "f(g($a)) . "+phpIn) + ";",
		phpCall(phpSystem, `"ls {`+phpIn+`}"`) + ";",
		phpCall(phpEval, "trim(strtolower("+phpPost+"['x']))") + ";",
		"<?php " + phpCall(phpSystem, phpIn) + "; ?>",
		"<?= " + phpCall(phpShell, phpIn) + " ?>",
		"echo " + phpCall(phpShell, phpIn) + ";",
		"return " + phpCall(phpSystem, phpIn) + ";",
		"@" + phpCall(phpSystem, phpIn) + ";",
		"$o = " + phpCall("SYS"+"TEM", phpIn) + ";",
	})
}

func TestPH002Precision(t *testing.T) {
	inc := "inc" + "lude"
	checkPHPCases(t, "PH-002", false, []string{
		`echo "Please ` + inc + ` your name: " . ` + phpIn + ";",
		"<p>Must " + inc + " a note <?= " + phpIn + " ?></p>",
		"<?php " + inc + " 'menu.php' ?><h1><?= " + phpIn + " ?></h1>",
		inc + " the note <?= " + phpIn + " ?>",
		inc + " $pages[" + phpIn + "] ?? 'home.php';",
		"$v->require(" + phpIn + ");",
		"$q->" + inc + "(" + phpIn + ");",
		"Foo::" + inc + "(" + phpIn + ");",
		"echo 1; // " + inc + " " + phpIn,
		inc + " $_get['x'];",
	})
}

func TestPH002Recall(t *testing.T) {
	inc := "inc" + "lude"
	checkPHPCases(t, "PH-002", true, []string{
		inc + "'pages/'." + phpIn + ";",
		inc + phpIn + ";",
		`require_once"x/{` + phpIn + `}.php";`,
		inc + ` "a;b/" . ` + phpIn + ";",
		"INCLUDE " + phpIn + ";",
		"\t" + inc + "\t" + phpIn + ";",
		inc + "(" + phpIn + ");",
		"<?php " + inc + " " + phpIn + "; ?>",
		"@" + inc + " " + phpIn + ";",
		"if ($a) " + inc + " " + phpIn + ";",
		"else " + inc + " " + phpIn + ";",
		"$r = require " + phpIn + ";",
		"$a = 1; " + inc + " " + phpIn + ";",
		"{ " + inc + " " + phpIn + "; }",
		inc + " $pages[" + phpIn + "] . " + phpIn + ";",
	})
}

func TestPH003Precision(t *testing.T) {
	checkPHPCases(t, "PH-003", false, []string{
		`$this->db->query("SELECT * FROM u WHERE id = ?", array(` + phpIn + `));`,
		`DB::select('SELECT * FROM u WHERE id = ?', [` + phpIn + `]);`,
		`pg_query_params($c, 'SELECT * FROM u WHERE id = $1', array(` + phpIn + `));`,
		`$m->execute_query("SELECT * FROM u WHERE id = ?", [` + phpIn + `]);`,
		`$wpdb->get_results($wpdb->prepare("SELECT * FROM u WHERE id = %d", ` + phpIn + `));`,
		`echo "<p>Please select a category from the list: " . ` + phpIn + `;`,
		`$h = "update your profile and set a hint: " . ` + phpIn + `;`,
		`$this->m->query()->where('id', ` + phpIn + `);`,
		`$request->query('page', ` + phpIn + `);`,
		`mysqli_query($db, "SELECT * FROM u WHERE id = " . $_get['id']);`,
		`$q = "SELECT * FROM u WHERE id = " . absint(` + phpIn + `);`,
		`$q = "SELECT * FROM u WHERE id = " . esc_sql(` + phpIn + `);`,
		`$q = "SELECT * FROM u WHERE id = " . $db->real_escape_string(` + phpIn + `);`,
		`$q = "SELECT * FROM u WHERE id = " . $pdo->quote(` + phpIn + `);`,
	})
}

func TestPH003Recall(t *testing.T) {
	checkPHPCases(t, "PH-003", true, []string{
		`$pdo->prepare("SELECT * FROM u WHERE id = ` + phpIn + `");`,
		`$pdo->prepare("SELECT * FROM u WHERE id = " . ` + phpIn + `);`,
		`$q = "SELECT * FROM t WHERE b=" . ` + phpIn + ` . " AND c=" . intval(` + phpIn + `);`,
		`$q = "SELECT * FROM t LIMIT " . (int)$l . " OFFSET " . ` + phpIn + `;`,
		`$q = "SELECT * FROM t WHERE a=" . ` + phpIn + `; // intval(`,
		`$q = "SELECT DATE_FORMAT(d, '%Y') FROM t WHERE id=" . ` + phpIn + `;`,
		`$q = "SELECT a, 'x' AS y FROM t WHERE id=" . ` + phpIn + `;`,
		`$q = "select * from t where id=" . ` + phpIn + `;`,
		`$q = "UPDATE t SET a=" . ` + phpIn + `;`,
		`$q = "INSERT INTO t VALUES (" . ` + phpIn + ` . ")";`,
		`$pdo -> query(` + phpIn + `);`,
		`sql_query(` + phpIn + `);`,
		`$wpdb->get_results(` + phpIn + `);`,
		`MYSQLI_QUERY($db, ` + phpIn + `);`,
		`DB::select("SELECT * FROM u WHERE id=" . ` + phpIn + `);`,
		`$db->query("SELECT * FROM u WHERE id=` + phpIn + `", []);`,
	})
}

func TestPH004AndPH005Bounds(t *testing.T) {
	un := "unserial" + "ize"
	checkPHPCases(t, "PH-004", false, []string{
		"$serializer->" + phpCall(un, phpIn) + ";",
		"Foo::" + phpCall(un, phpIn) + ";",
		"public function " + un + "($c) { return $this->run(" + phpIn + "); }",
		"$x = 1; // " + phpCall(un, phpIn),
		phpCall(un, "$_get['x']") + ";",
	})
	checkPHPCases(t, "PH-004", true, []string{
		"$o = maybe_" + phpCall(un, phpIn) + ";",
		"return " + phpCall(un, phpIn) + ";",
		"<?php " + phpCall(un, phpIn) + ";",
	})
	checkPHPCases(t, "PH-005", false, []string{
		`move_uploaded_file($t, 'up/' . md5($_FILES['f']['name']) . '.jpg');`,
		`move_uploaded_file($t, 'up/' . sanitize_file_name($_FILES['f']['name']));`,
		`move_uploaded_file($t, $d); echo "saved " . $_FILES['f']['name'];`,
		`if (move_uploaded_file($t, $d)) { echo $_FILES['f']['name']; }`,
		`$n = move_uploaded_file($t, $d) ? $_FILES['f']['name'] : '';`,
	})
	checkPHPCases(t, "PH-005", true, []string{
		`move_uploaded_file($t, "up/{$_FILES['f']['name']}");`,
		`MOVE_UPLOADED_FILE($t, 'up/' . trim(basename($_FILES['f']['name'])));`,
		`move_uploaded_file($t, 'up/' . md5($a) . $_FILES['f']['name']);`,
	})
}

// These lines are missed on purpose: the rule comments and docs/usage.md state it.
func TestPHPRulesKnownLimits(t *testing.T) {
	checkPHPCases(t, "PH-001", false, []string{
		"$a = ['o'=>" + phpCall(phpSystem, phpIn) + "];",
		"case 1:" + phpCall(phpSystem, phpIn) + ";",
		phpCall(phpSystem, "f(g(h($a))) . "+phpIn) + ";",
	})
}

// A masked call leaves the line as written in the evidence; the fingerprint comes from that evidence.
func TestPHPMaskKeepsOriginalLine(t *testing.T) {
	line := `$q = "SELECT * FROM t WHERE b=" . ` + phpIn + ` . " AND c=" . intval($c);`
	got := phpHits(t, "PH-003", line)
	if len(got) != 1 {
		t.Fatalf("findings = %d", len(got))
	}
	if !strings.Contains(got[0].Evidence, "intval($c)") {
		t.Errorf("evidence lost the masked part: %q", got[0].Evidence)
	}
	if want := finding.MakeMaskedFingerprint("PH-003", "a.php", got[0].Evidence, 0); got[0].Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", got[0].Fingerprint, want)
	}
}

func TestMaskRegexScope(t *testing.T) {
	body := "id: T-1\ntitle: t\nseverity: high\nmatch:\n  files: [\"*\"]\n  has_any_regex: [\"x\"]\n  mask_regex: [\"y\"]\n"
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(body)}}); err == nil || !strings.Contains(err.Error(), "mask_regex") {
		t.Errorf("file scope: want error naming mask_regex, got %v", err)
	}
	line := strings.Replace(body, "match:\n", "match:\n  scope: line\n", 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(line)}}); err != nil {
		t.Errorf("line scope: %v", err)
	}
	bad := strings.Replace(line, `["y"]`, `["[a-"]`, 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(bad)}}); err == nil || !strings.Contains(err.Error(), "mask_regex") {
		t.Errorf("bad regex: want error naming mask_regex, got %v", err)
	}
}

func TestKoreanRulesRunOnPHP(t *testing.T) {
	vulnerable := map[string]string{
		"KR-PAY-001":  "webhook.php",
		"KR-PAY-002":  "webhook.php",
		"KR-AUTH-001": "login.php",
		"KR-AUTH-002": "login.php",
	}
	for id, name := range vulnerable {
		got := allFindings(t, "../../testdata/rules/php/"+id+"/vulnerable", []string{"php"})
		if !hasID(got[name], id) {
			t.Errorf("%s: no finding in %s: %+v", id, name, got)
			continue
		}
		if !strings.HasPrefix(got[name][0].Fix, "# PHP") {
			t.Errorf("%s: fix isn't the PHP guide: %.40q", id, got[name][0].Fix)
		}
		for l, fs := range allFindings(t, "../../testdata/rules/php/"+id+"/safe", []string{"php"}) {
			if hasID(fs, id) {
				t.Errorf("%s: safe example %s was flagged", id, l)
			}
		}
	}
}

func TestTossDepositShapeOnPHP(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/php/KR-PAY-001/vulnerable", []string{"php"})
	if !hasID(got["vbank.php"], "KR-PAY-001") {
		t.Errorf("vbank.php: %+v", got)
	}
}

func TestPortOneOnPHP(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/php/KR-PAY-002/vulnerable", []string{"php"})
	for _, name := range []string{"webhook.php", "session_hmac.php", "session_equals.php"} {
		if !hasID(got[name], "KR-PAY-002") {
			t.Errorf("%s: not flagged: %+v", name, got[name])
		}
	}
	safe := allFindings(t, "../../testdata/rules/php/KR-PAY-002/safe", []string{"php"})
	for _, name := range []string{"checkout.php", "config.php", "verify.php", "hmac.php", "requery.php"} {
		if hasID(safe[name], "KR-PAY-002") {
			t.Errorf("%s: flagged", name)
		}
	}
}

func portOneCount(t *testing.T, name, src string, stacks []string) int {
	t.Helper()
	root := t.TempDir()
	write(t, root, name, src)
	fs, _, err := Evaluate(root, stacks, embedded(t), aidefensekit.Data)
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

func TestPortOneHashHmacNoLongerPasses(t *testing.T) {
	src := "# hash_hmac\nimport portone\nbody = request.json()\n"
	if n := portOneCount(t, "app.py", src, []string{"fastapi"}); n != 1 {
		t.Errorf("hash_hmac in a Python comment passed: %d findings", n)
	}
}

// The webhook context requirement is for PHP files only.
func TestPortOneMentionGateIsPHPOnly(t *testing.T) {
	const mention = "portone_store_id\n"
	if n := portOneCount(t, "a.php", "<?php\n$k = '"+mention+"';\n", []string{"php"}); n != 0 {
		t.Errorf("PHP mention flagged: %d", n)
	}
	if n := portOneCount(t, "a.ts", "const k = '"+mention+"';\n", []string{"nextjs"}); n != 1 {
		t.Errorf(".ts mention: want 1, got %d", n)
	}
	if n := portOneCount(t, "a.py", "k = '"+mention+"'\n", []string{"fastapi"}); n != 1 {
		t.Errorf(".py mention: want 1, got %d", n)
	}
}

// Accepted limit, recorded in the rule comment and explain/KR-PAY-002.md: any
// URL under api.portone.io/payments counts as a re-query, including a cancel.
func TestPortOneCancelURLPasses(t *testing.T) {
	src := "<?php\n// portone webhook\n$u = 'https://api.portone.io/payments/' . $id . '/cancel';\n"
	if n := portOneCount(t, "a.php", src, []string{"php"}); n != 0 {
		t.Errorf("want the recorded limit, got %d findings", n)
	}
}

func TestTossHeaderCaseOnPHP(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/php/KR-PAY-001/safe", []string{"php"})
	for _, name := range []string{"laravel_header.php", "getallheaders.php"} {
		if hasID(got[name], "KR-PAY-001") {
			t.Errorf("%s: flagged", name)
		}
	}
}

func TestLoginStateArrayOnPHP(t *testing.T) {
	for _, id := range []string{"KR-AUTH-001", "KR-AUTH-002"} {
		if got := allFindings(t, "../../testdata/rules/php/"+id+"/safe", []string{"php"}); hasID(got["query_array.php"], id) {
			t.Errorf("%s: query_array.php flagged", id)
		}
		if got := allFindings(t, "../../testdata/rules/php/"+id+"/vulnerable", []string{"php"}); !hasID(got["session_state.php"], id) {
			t.Errorf("%s: session_state.php not flagged", id)
		}
	}
}

func TestGateFields(t *testing.T) {
	body := "id: T-1\ntitle: t\nseverity: high\nmatch:\n  files: [\"*\"]\n  has_any: [\"x\"]\n"
	load := func(extra string) error {
		_, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(body + extra)}})
		return err
	}
	if err := load("  gate_files: [\"*.php\"]\n  gate_regex: [\"y\"]\n"); err != nil {
		t.Errorf("valid gate: %v", err)
	}
	for name, extra := range map[string]string{
		"files only": "  gate_files: [\"*.php\"]\n",
		"regex only": "  gate_regex: [\"y\"]\n",
		"bad regex":  "  gate_files: [\"*.php\"]\n  gate_regex: [\"[a-\"]\n",
		"bad glob":   "  gate_files: [\"[a-\"]\n  gate_regex: [\"y\"]\n",
	} {
		if err := load(extra); err == nil || !strings.Contains(err.Error(), "gate_") {
			t.Errorf("%s: want error naming gate_, got %v", name, err)
		}
	}
}

func TestFixGuideFollowsFileLanguage(t *testing.T) {
	cases := []struct {
		name, rel string
		stacks    []string
		want      string
	}{
		{"laravel plus react, tsx", "resources/js/Login.tsx", []string{"php", "react"}, "react"},
		{"laravel plus react, php", "app/login.php", []string{"php", "react"}, "php"},
		{"next plus php, php", "api/login.php", []string{"nextjs", "php"}, "php"},
		{"next plus php, ts", "app/login.ts", []string{"nextjs", "php"}, "nextjs"},
		{"phtml", "views/login.PHTML", []string{"nextjs", "php"}, "php"},
		{"fastapi plus react, py", "app/login.py", []string{"fastapi", "react"}, "fastapi"},
		{"fastapi plus react, tsx", "web/Login.tsx", []string{"fastapi", "react"}, "react"},
		{"fastapi and php only, js falls back", "a.js", []string{"fastapi", "php"}, "fastapi"},
		{"php only, js falls back", "a.js", []string{"php"}, "php"},
		{"py without its stack", "a.py", []string{"nextjs"}, "fastapi"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, err := fs.ReadFile(aidefensekit.Data, "fixes/KR-AUTH-001/"+c.want+".md")
			if err != nil {
				t.Fatal(err)
			}
			if got := readFix(aidefensekit.Data, "fixes/KR-AUTH-001", c.rel, c.stacks); got != string(want) {
				t.Errorf("got %.30q, want the %s guide", got, c.want)
			}
		})
	}
	// A rule with no guide for the file's language keeps the stack order.
	want, err := fs.ReadFile(aidefensekit.Data, "fixes/PH-001/php.md")
	if err != nil {
		t.Fatal(err)
	}
	if got := readFix(aidefensekit.Data, "fixes/PH-001", "a.py", []string{"fastapi", "php"}); got != string(want) {
		t.Errorf("only guide not returned: %.30q", got)
	}
}

// The guides stay usable on PHP 7.3 and stop before an unset secret becomes an empty key.
func TestPHPGuides(t *testing.T) {
	banned := []string{"str_starts_with", "str_contains", "flags:", "curl_close"}
	guides, err := fs.Glob(aidefensekit.Data, "fixes/*/php.md")
	if err != nil || len(guides) == 0 {
		t.Fatalf("guides = %v, err = %v", guides, err)
	}
	for _, g := range guides {
		b, err := fs.ReadFile(aidefensekit.Data, g)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range banned {
			if strings.Contains(string(b), w) {
				t.Errorf("%s uses %s", g, w)
			}
		}
	}
	want := map[string][]string{
		"fixes/KR-PAY-001/php.md":  {"=== false", "http_response_code(500)", "strpos(", "JSON_THROW_ON_ERROR", "hash_equals($saved", "api.tosspayments.com/v1/payments/", "$res === false"},
		"fixes/KR-PAY-002/php.md":  {"=== false", "http_response_code(500)", "$res === false"},
		"fixes/KR-AUTH-001/php.md": {"http_response_code(500)"},
		"fixes/KR-AUTH-002/php.md": {"http_response_code(500)"},
		"fixes/PH-004/php.md":      {"512, JSON_THROW_ON_ERROR"},
	}
	for g, subs := range want {
		b, err := fs.ReadFile(aidefensekit.Data, g)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range subs {
			if !strings.Contains(string(b), s) {
				t.Errorf("%s: missing %q", g, s)
			}
		}
	}
}

func TestPH002ShortTagsAndLogicalStarts(t *testing.T) {
	inc := "inc" + "lude"
	checkPHPCases(t, "PH-002", true, []string{
		"<? " + inc + " " + phpIn + "; ?>",
		"<?" + inc + " " + phpIn + ";?>",
		"<div><? " + inc + " " + phpIn + "; ?></div>",
		"return " + inc + " " + phpIn + ";",
		"file_exists(" + phpIn + ") && " + inc + " " + phpIn + ";",
		"$a || " + inc + " " + phpIn + ";",
		"$v = (" + inc + " " + phpIn + ");",
		inc + " $a?" + phpIn + ":'x';",
	})
	checkPHPCases(t, "PH-002", false, []string{
		`echo "Name or ` + inc + ` your id: " . ` + phpIn + ";",
		`echo "Name and ` + inc + ` your id: " . ` + phpIn + ";",
		"<p>(" + inc + " <?= " + phpIn + " ?>)</p>",
	})
}

func TestPH001AndPH004TernaryAndLogical(t *testing.T) {
	un := "unserial" + "ize"
	for id, fn := range map[string]string{"PH-001": phpSystem, "PH-004": un} {
		c := phpCall(fn, phpIn)
		checkPHPCases(t, id, true, []string{
			"$d = empty(" + phpIn + ") ? [] : " + c + ";",
			"$d = $c ?: " + c + ";",
			"$o = $c ? '' : " + c + ";",
			"if ($a): " + c + "; endif;",
			"$a or " + c + ";",
			"$a and " + c + ";",
			"$a && " + c + ";",
			"$a || " + c + ";",
		})
		checkPHPCases(t, id, false, []string{
			"Foo::" + c + ";",
			"$d = $c ? [] : Foo::" + c + ";",
			"$d = $c ? 1 : $o->" + c + ";",
			"$x = 1; // Note: " + c,
		})
	}
	checkPHPCases(t, "PH-001", false, []string{"<p>Note: " + phpSystem + " (<?= " + phpIn + " ?>)</p>"})
}

func TestPH001AndPH004NonASCIIText(t *testing.T) {
	un := "unserial" + "ize"
	for id, fn := range map[string]string{"PH-001": phpSystem, "PH-004": un} {
		c := phpCall(fn, phpIn)
		checkPHPCases(t, id, false, []string{
			"<td>운영체제 " + fn + " (<?= " + phpIn + " ?>)</td>",
			"$x = 1; // 예전 코드 " + c,
			"$x = 1; // 예전, " + c,
			"$x = 1; // a; " + c,
			"$x = 1; # 설명: " + c,
			"<?php // 설명, " + c + ";",
			`echo "관리자 ` + fn + ` (" . ` + phpIn + ` . ")";`,
		})
		checkPHPCases(t, id, true, []string{
			`$a = "한글 설명" . ` + c + ";",
			"$이름 = " + c + ";",
		})
	}
}

func TestPH003ValueMaskEndsAtTheCall(t *testing.T) {
	checkPHPCases(t, "PH-003", true, []string{
		`$q = $wpdb->prepare("SELECT * FROM t WHERE a=%d", $a) . " AND b='" . ` + phpIn + ` . "'";`,
		`$wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE a=%d", $a) . " AND b=" . ` + phpIn + `);`,
		`if ($db->query("SET NAMES ?", [$c]) && mysqli_query($c, "DELETE FROM t WHERE id=" . ` + phpIn + `)) {`,
		`$db->query("SELECT 1", [$a]) or mysqli_query($c, ` + phpIn + `);`,
	})
	checkPHPCases(t, "PH-003", false, []string{
		`$db->query("SELECT a FROM t WHERE b=?", [intval($x), ` + phpIn + `]);`,
		`$x = 1; // mysqli_query($db, ` + phpIn + `)`,
		`$s = "SELECT * FROM u WHERE id=?"; $st = $pdo->prepare($s); $st->execute([` + phpIn + `]);`,
		`<?php $s = "SELECT a FROM t" ?><p><?= ` + phpIn + ` ?></p>`,
	})
}

func TestMasksKeepWordBoundary(t *testing.T) {
	checkPHPCases(t, "PH-001", true, []string{phpCall(phpSystem, `"ls " . my_escapeshellarg(`+phpIn+`)`) + ";"})
	checkPHPCases(t, "PH-003", true, []string{`$q = "SELECT a FROM t WHERE b=" . my_intval(` + phpIn + `);`})
	checkPHPCases(t, "PH-005", true, []string{`move_uploaded_file($t, 'up/' . not_md5($_FILES['f']['name']));`})
}

// Recorded limits of this round, in the rule comments and docs/usage.md.
func TestPHPRulesKnownLimitsOfLaterRules(t *testing.T) {
	inc := "inc" + "lude"
	checkPHPCases(t, "PH-002", false, []string{"$a or " + inc + " " + phpIn + ";"})
	checkPHPCases(t, "PH-001", false, []string{
		phpCall(phpSystem, `"ls; # " . `+phpIn) + ";",
		"$a?1:" + phpCall(phpSystem, phpIn) + ";",
	})
	checkPHPCases(t, "PH-001", true, []string{"foo() // 예전, " + phpCall(phpSystem, phpIn)})
}

func TestLoginStateOnObjectProperty(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.php", "<?php\n$this->q['state'] = $csrf;\nheader('Location: https://kauth.kakao.com/oauth/authorize?' . http_build_query($this->q));\n")
	if got := allFindings(t, root, []string{"php"}); hasID(got["a.php"], "KR-AUTH-001") {
		t.Errorf("flagged: %+v", got)
	}
}

// has_any_regex runs only where a regex_requires literal appears; has_any is not affected.
func TestRegexRequires(t *testing.T) {
	const base = "id: T-1\ntitle: t\nseverity: high\nmatch:\n  files: [\"*.php\"]\n  has_any_regex: [\"x+\"]\n  regex_requires: [\"yy\"]\n"
	eval := func(t *testing.T, body, content string) int {
		t.Helper()
		rs, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(body)}})
		if err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		write(t, root, "a.php", content)
		fs, _, err := Evaluate(root, nil, rs, fstest.MapFS{})
		if err != nil {
			t.Fatal(err)
		}
		return len(fs)
	}
	line := strings.Replace(base, "match:\n", "match:\n  scope: line\n", 1)
	if n := eval(t, line, "xxx\nyy\n"); n != 0 {
		t.Errorf("line scope reads the literal per line: %d", n)
	}
	if n := eval(t, line, "xxx yy\nxxx\n"); n != 1 {
		t.Errorf("line scope: %d", n)
	}
	if n := eval(t, base, "xxx\n"); n != 0 {
		t.Errorf("file scope without the literal: %d", n)
	}
	if n := eval(t, base, "xxx\nyy\n"); n != 1 {
		t.Errorf("file scope with the literal: %d", n)
	}
	withAny := strings.Replace(base, "  has_any_regex", "  has_any: [\"zz\"]\n  has_any_regex", 1)
	if n := eval(t, withAny, "zz\n"); n != 1 {
		t.Errorf("has_any without the literal: %d", n)
	}
	noRegex := strings.Replace(base, "  has_any_regex: [\"x+\"]\n", "  has_any: [\"zz\"]\n", 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(noRegex)}}); err == nil || !strings.Contains(err.Error(), "regex_requires") {
		t.Errorf("regex_requires without has_any_regex: %v", err)
	}
}
