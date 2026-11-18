package rules

import (
	"strings"
	"testing"
	"testing/fstest"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// phpFileHits runs one rule over a file made of "<?php" and the given lines,
// so the first given line is line 2. Like phpHits, the dangerous shapes are
// joined in memory only.
func phpFileHits(t *testing.T, id string, lines ...string) []finding.Finding {
	t.Helper()
	return lineFindings(phpRule(t, id), "a.php", "<?php\n"+strings.Join(lines, "\n")+"\n", []string{"php"}, aidefensekit.Data)
}

var (
	phpInclude   = "inc" + "lude"
	phpUnser     = "unserial" + "ize"
	phpMoveFile  = "move_uploaded_" + "file"
	phpReqIP     = "$_REQUEST['ip']"
	phpUploadTmp = "$_FILES['f']['tmp_name']"
)

// Input put in a variable and used on a later line of the same function is
// found on the line that uses it, as a suspect finding with that line as evidence.
func TestPHPTrackedInputFindsLaterUse(t *testing.T) {
	cases := []struct {
		name, id string
		line     int
		lines    []string
	}{
		{"command", "PH-001", 3, []string{
			"$t = " + phpReqIP + ";",
			"$c = " + phpCall(phpShell, "'ping ' . $t") + ";",
		}},
		{"command after trim and replace", "PH-001", 4, []string{
			"$t = trim(" + phpReqIP + ");",
			"$t = str_replace(array_keys($s), $s, $t);",
			"$c = " + phpCall(phpShell, "'ping ' . $t") + ";",
		}},
		{"include", "PH-002", 3, []string{
			"$file = $_GET['page'];",
			phpCall(phpInclude, "$file") + ";",
		}},
		{"sql string", "PH-003", 3, []string{
			"$id = $_GET['id'];",
			`$q = "SELECT a FROM u WHERE id = '$id';";`,
		}},
		{"cookie object", "PH-004", 3, []string{
			"$d = $_COOKIE['d'];",
			"$o = " + phpCall(phpUnser, "$d") + ";",
		}},
		{"upload name appended", "PH-005", 4, []string{
			`$p = "up/";`,
			"$p .= basename($_FILES['f']['name']);",
			"if (!" + phpCall(phpMoveFile, phpUploadTmp+", $p") + ") {",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := phpFileHits(t, c.id, c.lines...)
			if len(got) != 1 {
				t.Fatalf("findings = %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Line != c.line || f.Confidence != finding.Suspect {
				t.Errorf("line %d, %v; want line %d, suspect", f.Line, f.Confidence, c.line)
			}
			if want := truncate(maskEvidenceFor("a.php", strings.TrimSpace(c.lines[c.line-2]))); f.Evidence != want {
				t.Errorf("evidence = %q, want the line as written %q", f.Evidence, want)
			}
		})
	}
}

// A line with the input written in it keeps the rule's own confidence even
// when a tracked variable is on the same line.
func TestPHPTrackedInputKeepsDirectConfidence(t *testing.T) {
	got := phpFileHits(t, "PH-001",
		"$t = "+phpReqIP+";",
		phpCall(phpSystem, "$t . "+phpIn)+";",
	)
	if len(got) != 1 || got[0].Confidence != finding.Certain {
		t.Fatalf("findings = %+v", got)
	}
}

func TestPHPTrackedInputLeavesSafeUsesAlone(t *testing.T) {
	cases := []struct {
		name, id string
		lines    []string
	}{
		{"overwritten with a constant", "PH-001", []string{
			"$t = " + phpIn + ";",
			"$t = 'localhost';",
			phpCall(phpSystem, "'ping ' . $t") + ";",
		}},
		{"rebuilt from another variable", "PH-001", []string{
			"$t = " + phpReqIP + ";",
			"$t = stripslashes($t);",
			"$o = explode('.', $t);",
			"$t = $o[0] . '.' . $o[1];",
			phpCall(phpShell, "'ping ' . $t") + ";",
		}},
		{"escaped by the rule's own mask", "PH-001", []string{
			"$t = " + phpIn + ";",
			phpCall(phpSystem, "'ping ' . escapeshellarg($t)") + ";",
		}},
		{"converted to a number", "PH-001", []string{
			"$n = intval(" + phpIn + ");",
			phpCall(phpSystem, "'kill ' . $n") + ";",
		}},
		{"converted again to a number", "PH-003", []string{
			"$id = $_GET['id'];",
			"$id = intval ($id);",
			`$q = "SELECT a FROM u WHERE id = $id";`,
		}},
		{"cast to a number", "PH-003", []string{
			"$id = (int) $_GET['id'];",
			`$q = "SELECT a FROM u WHERE id = $id";`,
		}},
		{"escaped for sql", "PH-003", []string{
			"$id = $_POST['id'];",
			"$id = mysqli_real_escape_string($db, $id);",
			`$q = "SELECT a FROM u WHERE id = '$id'";`,
		}},
		{"hashed", "PH-003", []string{
			"$p = $_POST['password'];",
			"$p = md5( $p );",
			`$q = "SELECT a FROM u WHERE p = '$p'";`,
		}},
		{"only checked", "PH-001", []string{
			"$has = isset(" + phpIn + ");",
			phpCall(phpSystem, "'ls ' . $has") + ";",
		}},
		{"session is not request input", "PH-003", []string{
			"$id = $_SESSION['id'];",
			`$q = "SELECT a FROM u WHERE id = '$id'";`,
		}},
		{"another function", "PH-001", []string{
			"$t = " + phpIn + ";",
			"function run($x) {",
			phpCall(phpSystem, "$t") + ";",
		}},
		{"longer name", "PH-001", []string{
			"$t = " + phpIn + ";",
			phpCall(phpSystem, "$t_safe") + ";",
		}},
		{"assignment in a comment", "PH-001", []string{
			"// $t = " + phpIn + ";",
			phpCall(phpSystem, "$t") + ";",
		}},
		{"comparison is not assignment", "PH-001", []string{
			"if ($t == " + phpIn + ") {",
			phpCall(phpSystem, "$t") + ";",
		}},
		{"random upload name", "PH-005", []string{
			"$n = $_FILES['f']['name'];",
			"$p = 'up/' . bin2hex(random_bytes(16)) . '.jpg';",
			phpCall(phpMoveFile, phpUploadTmp+", $p") + ";",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := phpFileHits(t, c.id, c.lines...); len(got) != 0 {
				t.Errorf("flagged: %+v", got)
			}
		})
	}
}

// Recorded limits of tracking, in the rule comments and docs/usage.md.
func TestPHPTrackedInputKnownLimits(t *testing.T) {
	// A second variable built from the first is not followed.
	if got := phpFileHits(t, "PH-001",
		"$t = "+phpReqIP+";",
		"$c = 'ping ' . $t;",
		phpCall(phpShell, "$c")+";",
	); len(got) != 0 {
		t.Errorf("second variable: %+v", got)
	}
	// Input and use in different files (a page that sets the path, another that includes it).
	if got := phpFileHits(t, "PH-002", phpCall(phpInclude, "$file")+";"); len(got) != 0 {
		t.Errorf("other file: %+v", got)
	}
}

func TestInputVarRegexScope(t *testing.T) {
	body := "id: T-1\ntitle: t\nseverity: high\nmatch:\n  files: [\"*\"]\n  has_any_regex: [\"x\"]\n  input_var_regex: [\"y\"]\n"
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(body)}}); err == nil || !strings.Contains(err.Error(), "input_var_regex") {
		t.Errorf("file scope: want error naming input_var_regex, got %v", err)
	}
	line := strings.Replace(body, "match:\n", "match:\n  scope: line\n", 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(line)}}); err != nil {
		t.Errorf("line scope: %v", err)
	}
	bad := strings.Replace(line, `["y"]`, `["[a-"]`, 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(bad)}}); err == nil || !strings.Contains(err.Error(), "input_var_regex") {
		t.Errorf("bad regex: want error naming input_var_regex, got %v", err)
	}
}
