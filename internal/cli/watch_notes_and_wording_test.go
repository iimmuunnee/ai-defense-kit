package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// M2: the notes do not vanish on a round where another read fails.
func TestWatchNotesSurviveAPartialRead(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="/a.js"></script><script src="https://cdn.example.invalid/x.js"></script>`)
		case fail.Load():
			w.WriteHeader(500)
		default:
			fmt.Fprint(w, "a")
		}
	}))
	defer srv.Close()
	w := newWsp(t)
	cfg := fmt.Sprintf("targets:\n  - key: page\n    kind: web-scripts\n    options:\n      url: \"%s/\"\n", srv.URL)
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mustInit(t, w)
	fail.Store(true)
	code, out, errs := w.run("check", "--format", "json")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if _, _, notes := parseReport(t, out).check("watch/page"); !strings.Contains(strings.Join(notes, " "), "not-fetched") {
		t.Errorf("the not-fetched note is gone: %v", notes)
	}
}

func TestWatchDelegateNoteSurvivesAPartialRead(t *testing.T) {
	chain := newFakeChain(t)
	chain.code = delegationCode(testDelA)
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	chain.mu.Lock()
	chain.blockAge = 2 * time.Hour
	chain.mu.Unlock()
	code, out, _ := w.run("check", "--format", "json")
	if code != 2 {
		t.Fatalf("code=%d\n%s", code, out)
	}
	if _, _, notes := parseReport(t, out).check("watch/hot"); !strings.Contains(strings.Join(notes, " "), "allowed_delegates") {
		t.Errorf("the delegate note is gone: %v", notes)
	}
}

// M3: a name from the export reaches the terminal cleaned.
func TestWatchWarningsAreCleanedForTheTerminal(t *testing.T) {
	esc := podEntry{"ops", "dbg", "sh\x1b[31m", "docker.io/library/busybox:1", unreadDigB, ""}
	w, file := podsWsp(t, `      allowed_registries: ["registry.example.com"]`+"\n", podsJSON(esc))
	code, out, errs := w.run("init")
	if code != 0 || strings.ContainsRune(errs, 0x1b) {
		t.Errorf("init: code=%d\n%q\n%q", code, out, errs)
	}
	next := esc
	next.digest = unreadDigA
	if err := os.WriteFile(file, []byte(podsJSON(next)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = w.run("accept", "cluster", "--note", "x")
	if code != 0 || strings.ContainsRune(errs, 0x1b) || strings.ContainsRune(out, 0x1b) {
		t.Errorf("accept: code=%d\n%q\n%q", code, out, errs)
	}
}

// M11: .adkignore does not apply to watch, so its report does not advise it.
func TestWatchReportDoesNotAdviseADKIgnore(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	code, out, errs := w.run("check")
	if code != 1 || !strings.Contains(out, "지문") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, ".adkignore") {
		t.Errorf("the watch report advises .adkignore:\n%s", out)
	}
}

// M14: a plain http page gets the note an RPC gets, without its address.
func TestPlainHTTPPageNote(t *testing.T) {
	tg := watch.Target{Key: "p", Kind: "web-scripts", Options: map[string]any{"url": "http://shop.example.com/?token=abcdef123"}}
	notes := strings.Join(targetNotes(tg), " ")
	if !strings.Contains(notes, "암호화") || !strings.Contains(notes, "페이지") {
		t.Errorf("notes = %q", notes)
	}
	if strings.Contains(notes, "shop.example.com") || strings.Contains(notes, "abcdef123") {
		t.Errorf("the note shows the address: %q", notes)
	}
	tg.Options["url"] = "https://shop.example.com/"
	if notes := targetNotes(tg); len(notes) != 0 {
		t.Errorf("https: %v", notes)
	}
}

// M14: every kind in one config, with CronJob runs going by.
func TestWatchMixedKindsInOneConfig(t *testing.T) {
	chain := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	acct := xrplAddr(1)
	x := newFakeXRPL(t, acct)
	t.Setenv("ADK_T_X", x.srv.URL)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<script src="/a.js"></script>`)
			return
		}
		fmt.Fprint(w, "a")
	}))
	defer site.Close()
	root := t.TempDir()
	writeRepoFile(t, root, "package-lock.json", "1")
	dir := t.TempDir()
	pods := filepath.Join(dir, "pods.json")
	run := func(id string) string {
		return `{"kind":"List","items":[{"kind":"Pod","metadata":{"name":"backup-` + id + `-abcde","namespace":"ops","ownerReferences":[{"kind":"Job","name":"backup-` + id + `","controller":true}]},"status":{"phase":"Succeeded","containerStatuses":[{"name":"c","image":"registry.example.com/backup:1","imageID":"registry.example.com/backup@` + unreadDigA + `"}]}}]}`
	}
	if err := os.WriteFile(pods, []byte(run("29000100")), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newWsp(t)
	cfg := fmt.Sprintf(`targets:
  - key: wallet
    kind: evm-wallet
    options: {chain_id: 1, address: "%s", type: eoa, rpc_url_env: "ADK_T_RPC_A,ADK_T_RPC_B"}
  - key: xrp
    kind: xrpl-wallet
    options: {address: "%s", rpc_url_env: "ADK_T_X"}
  - key: page
    kind: web-scripts
    options: {url: "%s/"}
  - key: repo
    kind: repo-files
    options: {root: "%s"}
  - key: cluster
    kind: k8s-pods
    options: {file: "%s"}
`, testWallet, acct, site.URL, filepath.ToSlash(root), filepath.ToSlash(pods))
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mustInit(t, w)
	if code, out, errs := w.run("check", "--format", "json"); code != 0 {
		t.Fatalf("clean: code=%d\n%s\n%s", code, out, errs)
	}
	// Next run of the same CronJob: no change.
	if err := os.WriteFile(pods, []byte(run("29000105")), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Fatalf("a new CronJob run: code=%d\n%s", code, out)
	}
	// Each kind speaks with its own number, together.
	chain.setCode(delegationCode(testDelA))
	x.set(func() { x.flags = 1 << 20 })
	writeRepoFile(t, root, "package-lock.json", "2")
	if err := os.WriteFile(pods, []byte(strings.ReplaceAll(run("29000110"), unreadDigA, unreadDigB)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := w.run("check", "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s", code, out)
	}
	got := map[string]string{}
	for _, f := range d3Findings(t, out) {
		got[f.Location] = f.ID
	}
	want := map[string]string{"wallet": "WA-001", "xrp": "WA-002", "repo": "WA-102", "cluster": "WA-103"}
	for k, id := range want {
		if got[k] != id {
			t.Errorf("%s: %s, want %s (all %v)", k, got[k], id, got)
		}
	}
}
