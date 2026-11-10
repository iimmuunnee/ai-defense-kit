package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoWsp watches every yml file under a fresh root.
func repoWsp(t *testing.T, files map[string]string) (*wsp, string) {
	t.Helper()
	w := newWsp(t)
	root := t.TempDir()
	for name, body := range files {
		writeRepoFile(t, root, name, body)
	}
	cfg := fmt.Sprintf("targets:\n  - key: repo\n    kind: repo-files\n    options:\n      root: \"%s\"\n      globs: [\"**/*.yml\"]\n", filepath.ToSlash(root))
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return w, root
}

func writeRepoFile(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWatchExpectLimitsWhatIsAccepted(t *testing.T) {
	w, root := repoWsp(t, map[string]string{"ci.yml": "ci", "deploy.yml": "deploy", "old.yml": "old"})
	mustInit(t, w)
	before := readFile(t, w.base)
	writeRepoFile(t, root, "ci.yml", "ci2")
	writeRepoFile(t, root, "deploy.yml", "deploy2")
	writeRepoFile(t, root, "evil.yml", "evil")
	if err := os.Remove(filepath.Join(root, "old.yml")); err != nil {
		t.Fatal(err)
	}
	ci := "--expect=file:ci.yml=" + sha256Hex([]byte("ci2"))
	deploy := "--expect=file:deploy.yml=" + sha256Hex([]byte("deploy2"))
	evil := "--expect=file:evil.yml=" + sha256Hex([]byte("evil"))

	refused := func(want []string, args ...string) {
		t.Helper()
		code, out, errs := w.run("accept", append([]string{"repo", "--note", "검토"}, args...)...)
		if code != 2 {
			t.Errorf("%v: code=%d\n%s\n%s", args, code, out, errs)
		}
		for _, n := range want {
			if !strings.Contains(errs, n) {
				t.Errorf("%v: the refusal does not name %s:\n%s", args, n, errs)
			}
		}
		if readFile(t, w.base) != before || fileExists(w.history) {
			t.Fatalf("%v: a refused accept changed something", args)
		}
	}
	// The reviewer's one file does not bring the rest along.
	refused([]string{"file:deploy.yml", "file:evil.yml", "file:old.yml"}, ci)
	// A removal has to be named too.
	refused([]string{"file:old.yml"}, ci, deploy, evil)
	// A removal named with a value, or a file still there named as removed.
	refused([]string{"file:old.yml"}, ci, deploy, evil, "--expect=file:old.yml="+sha256Hex([]byte("old")))
	refused([]string{"file:evil.yml"}, ci, deploy, "--expect=file:evil.yml=", "--expect=file:old.yml=")
	// A field neither side has.
	refused([]string{"file:typo.yml"}, ci, deploy, evil, "--expect=file:old.yml=", "--expect=file:typo.yml=")

	code, out, errs := w.run("accept", "repo", "--note", "검토", ci, deploy, evil, "--expect=file:old.yml=")
	if code != 0 {
		t.Fatalf("all named: code=%d\n%s\n%s", code, out, errs)
	}
	e := baselineEntry(t, w, "repo")
	if _, has := e["file:old.yml"]; has || e["file:evil.yml"] != sha256Hex([]byte("evil")) {
		t.Errorf("baseline = %v", e)
	}
	if code, out, _ := w.run("check"); code != 0 {
		t.Errorf("check = %d\n%s", code, out)
	}
}

func TestWatchWithoutExpectStaysWholeTarget(t *testing.T) {
	w, root := repoWsp(t, map[string]string{"ci.yml": "ci", "old.yml": "old"})
	mustInit(t, w)
	writeRepoFile(t, root, "ci.yml", "ci2")
	writeRepoFile(t, root, "new.yml", "new")
	if err := os.Remove(filepath.Join(root, "old.yml")); err != nil {
		t.Fatal(err)
	}
	code, out, errs := w.run("accept", "repo", "--note", "전체")
	if code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	for _, f := range []string{"file:ci.yml", "file:new.yml", "file:old.yml"} {
		if !strings.Contains(out, f) {
			t.Errorf("the list of changes lacks %s:\n%s", f, out)
		}
	}
}

// A field name can hold "=", and a value can too.
func TestWatchExpectParsesEveryEqualsSign(t *testing.T) {
	w, root := repoWsp(t, map[string]string{"a=b.yml": "x", "a.yml": "y"})
	mustInit(t, w)
	writeRepoFile(t, root, "a=b.yml", "x2")
	code, out, errs := w.run("accept", "repo", "--note", "검토", "--expect=file:a=b.yml="+sha256Hex([]byte("x2")))
	if code != 0 {
		t.Fatalf("a name with =: code=%d\n%s\n%s", code, out, errs)
	}

	t.Run("two readings, the value decides", func(t *testing.T) {
		w, root := repoWsp(t, map[string]string{"p": "", "p.yml": "1", "p.yml=q.yml": "2"})
		mustInit(t, w)
		writeRepoFile(t, root, "p.yml=q.yml", "3")
		// "file:p.yml" with the value "q.yml=<hash>" is false; the other reading is true.
		if code, out, errs := w.run("accept", "repo", "--note", "검토", "--expect=file:p.yml=q.yml="+sha256Hex([]byte("3"))); code != 0 {
			t.Errorf("code=%d\n%s\n%s", code, out, errs)
		}
		// Neither reading is true: refused.
		if code, out, errs := w.run("accept", "repo", "--note", "검토", "--expect=file:p.yml=q.yml="+sha256Hex([]byte("9"))); code != 2 {
			t.Errorf("code=%d\n%s\n%s", code, out, errs)
		}
	})
}

func TestWatchExpectOnXRPLValueWithEquals(t *testing.T) {
	acct := xrplAddr(1)
	signer := xrplAddr(2)
	f := newFakeXRPL(t, acct)
	w := xrplWsp(t, acct, "ADK_T_X")
	t.Setenv("ADK_T_X", f.srv.URL)
	mustInit(t, w)
	f.set(func() {
		f.objects = `[{"LedgerEntryType":"SignerList","SignerQuorum":1,"SignerEntries":[{"SignerEntry":{"Account":"` + signer + `","SignerWeight":1}}]}]`
	})
	value := "quorum=1;" + signer + ":1"
	if code, out, errs := w.run("accept", "xrp-hot", "--note", "검토", "--expect", "signer_list="+value, "--expect", "regular_key="); code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if e := baselineEntry(t, w, "xrp-hot"); e["signer_list"] != value {
		t.Errorf("baseline = %v", e)
	}
}

// A first-time target has every field appearing: all of them must be named.
func TestWatchExpectOnANewTargetNamesEveryField(t *testing.T) {
	w, _ := oneWallet(t)
	w.writeCfg(wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	w.writeCfg(
		wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"},
		wTarget{key: "extra", addr: testWallet2, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	code, out, errs := w.run("accept", "extra", "--note", "추가", "--expect", "type=eoa")
	if code != 2 || !strings.Contains(errs, "address") {
		t.Errorf("code=%d\n%s\n%s", code, out, errs)
	}
}

func TestExpectTextsSayWhatItDoes(t *testing.T) {
	root := "../../"
	for _, p := range []string{"docs/watch.md", "explain/WA-101.md", "explain/WA-102.md", "explain/WA-103.md", "fixes/WA-101/watch.md", "fixes/WA-102/watch.md", "fixes/WA-103/watch.md"} {
		s := readFile(t, root+p)
		if !strings.Contains(s, "모두 적어야") {
			t.Errorf("%s does not say that every changing field must be named", p)
		}
		if !strings.Contains(s, "=`") && !strings.Contains(s, "=\"") {
			t.Errorf("%s does not say how to name a removal", p)
		}
		for _, bad := range []string{"`--expect`를 쓸 수 없", "항목 이름에 `=`가 들어 있으면 쓸 수 없", "`--expect`로 지정할 수 없", "남은 항목에만"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s still says %q", p, bad)
			}
		}
	}
}
