package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const d1Dir = "../../testdata/drills/d1"

// d1Site serves the drill page and one script whose content can be swapped,
// like a deploy would. It counts how often the script was read.
type d1Site struct {
	srv *httptest.Server

	mu       sync.Mutex
	script   string // file under testdata/drills/d1
	scriptHi int
}

func newD1Site(t *testing.T) *d1Site {
	t.Helper()
	s := &d1Site{script: "app.original.js"}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(d1Dir, name))
		if err != nil {
			t.Error(err)
		}
		return b
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(read("index.html"))
		case "/app.js":
			s.mu.Lock()
			name := s.script
			s.scriptHi++
			s.mu.Unlock()
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write(read(name))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *d1Site) swap(name string) { s.mu.Lock(); s.script = name; s.mu.Unlock() }
func (s *d1Site) reads() int       { s.mu.Lock(); defer s.mu.Unlock(); return s.scriptHi }

func writeWebConfig(t *testing.T, w *wsp, url string) {
	t.Helper()
	cfg := fmt.Sprintf("targets:\n  - key: shop\n    kind: web-scripts\n    options:\n      url: \"%s\"\n", url)
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// d1Token stands for a secret that someone put in the page address.
const d1Token = "TOKEN-must-not-appear-9f3a"

// TestDrillD1 runs the drill against a fake web server: the script is
// replaced, found, restored, and then replaced and restored between two
// checks, which check cannot see.
func TestDrillD1(t *testing.T) {
	site := newD1Site(t)
	w := newWsp(t)
	writeWebConfig(t, w, site.srv.URL+"/?token="+d1Token)
	var allOut strings.Builder
	note := func(out, errs string) { allOut.WriteString(out + errs) }

	code, out, errs := w.run("init")
	note(out, errs)
	if code != 0 {
		t.Fatalf("init = %d\n%s\n%s", code, out, errs)
	}
	firstCode, first, e := w.run("check", "--format", "json")
	note(first, e)
	if firstCode != 0 {
		t.Fatalf("step 1: code=%d\n%s", firstCode, first)
	}

	// The script is replaced.
	site.swap("app.replaced.js")
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	if code != 1 || !strings.Contains(out, "WA-101") || !strings.Contains(out, `"high"`) {
		t.Fatalf("step 2: code=%d\n%s", code, out)
	}
	var rep struct {
		Findings []struct {
			ID        string
			Location  string
			ExplainKo string `json:"explain_ko"`
			Fix       string
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Findings) != 1 {
		t.Fatalf("%v\n%s", err, out)
	}
	if f := rep.Findings[0]; f.ID != "WA-101" || f.Location != "shop" || f.ExplainKo == "" || f.Fix == "" {
		t.Errorf("finding = %+v", f)
	}

	// It is restored: clean, and the same output as the first check.
	site.swap("app.original.js")
	lastCode, last, e := w.run("check", "--format", "json")
	note(last, e)
	if lastCode != 0 {
		t.Fatalf("step 3: code=%d\n%s", lastCode, last)
	}
	if a, b := withoutTime(t, first), withoutTime(t, last); a != b {
		t.Errorf("step 3 differs from step 1:\n%s\n%s", a, b)
	}

	// Replaced and restored between two checks: check never reads the script
	// in between, so it cannot tell. This is a limit, written down in docs/watch.md.
	before := site.reads()
	site.swap("app.replaced.js")
	site.swap("app.original.js")
	if site.reads() != before {
		t.Fatal("the script was read without a check")
	}
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	if code != 0 || strings.Contains(out, "WA-101") {
		t.Errorf("skipped window: code=%d\n%s", code, out)
	}

	// A replaced script that is meant is recorded with accept, and then it is the baseline.
	site.swap("app.replaced.js")
	if code, _, errs := w.run("accept", "shop"); code != 2 || !strings.Contains(errs, "--note") {
		t.Errorf("accept without a note = %d\n%s", code, errs)
	}
	replaced, err := os.ReadFile(filepath.Join(d1Dir, "app.replaced.js"))
	if err != nil {
		t.Fatal(err)
	}
	field := "script:" + site.srv.URL + "/app.js"
	if code, _, errs := w.run("accept", "shop", "--note", "drill", "--expect", field+"=0000"); code != 2 {
		t.Errorf("accept with a wrong --expect = %d\n%s", code, errs)
	}
	code, out, e = w.run("accept", "shop", "--note", "drill: 배포 승인", "--expect", field+"="+sha256Hex(replaced))
	note(out, e)
	if code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, e)
	}
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Errorf("after accept: code=%d\n%s", code, out)
	}
	hist := readFile(t, w.history)
	if !strings.Contains(hist, "script:"+site.srv.URL+"/app.js") || !strings.Contains(hist, "drill") {
		t.Errorf("history = %s", hist)
	}

	// The token in the configured address reaches no output and no file.
	for _, p := range []string{w.base, w.history} {
		if strings.Contains(readFile(t, p), d1Token) {
			t.Errorf("%s holds the token", p)
		}
	}
	if strings.Contains(allOut.String(), d1Token) {
		t.Error("the token reached the output")
	}
}

// A deploy that moves the page's script to a host that is not listed is a
// change even though that host is never contacted.
func TestDrillD1NewOutsideScript(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		_, _ = w.Write([]byte("console.log('outside');"))
	}))
	t.Cleanup(outside.Close)

	var mu sync.Mutex
	extra := ""
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte("console.log('own');"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><script src="/app.js"></script>%s</html>`, extra)
	}))
	t.Cleanup(home.Close)

	w := newWsp(t)
	writeWebConfig(t, w, home.URL+"/")
	mustInit(t, w)
	mu.Lock()
	extra = fmt.Sprintf(`<script src="%s/skim.js?key=%s"></script>`, outside.URL, d1Token)
	mu.Unlock()
	code, out, errs := w.run("check", "--format", "json")
	if code != 1 || !strings.Contains(out, "WA-101") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if n := outsideHits.Load(); n != 0 {
		t.Errorf("the outside host was contacted %d times", n)
	}
	if strings.Contains(out+errs, d1Token) {
		t.Error("the query of the outside script reached the output")
	}
}

func TestRepoFilesCLI(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	wf := filepath.Join(repo, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	ci := filepath.Join(wf, "ci.yml")
	if err := os.WriteFile(ci, []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := newWsp(t)
	cfg := fmt.Sprintf("targets:\n  - key: repo\n    kind: repo-files\n    options:\n      root: \"%s\"\n", filepath.ToSlash(repo))
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mustInit(t, w)
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Fatalf("clean check = %d\n%s", code, out)
	}
	if err := os.WriteFile(ci, []byte("name: ci\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := w.run("check", "--format", "json")
	if code != 1 || !strings.Contains(out, "WA-102") {
		t.Fatalf("changed: code=%d\n%s", code, out)
	}
	if strings.Contains(out, "RPC 주소가 하나뿐") {
		t.Error("the single-RPC note appeared for a repo-files target")
	}
	if code, out, errs := w.run("accept", "repo", "--note", "워크플로 수정 승인"); code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Errorf("after accept: %d\n%s", code, out)
	}
	// A missing root cannot be verified.
	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := w.run("check", "--format", "json"); code != 2 {
		t.Errorf("missing root: code=%d", code)
	}
	// An empty root is refused at init.
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	w2 := newWsp(t)
	if err := os.WriteFile(w2.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w2.run("init"); code != 2 || !strings.Contains(errs, "파일을 하나도 찾지 못했습니다") {
		t.Errorf("init on an empty root = %d\n%s", code, errs)
	}
}

// A page whose scripts are all on a host that is not allowed has nothing to
// compare: init refuses it and points at allowed_hosts.
func TestWebAllScriptsOutsideIsRefusedAtInit(t *testing.T) {
	var hits atomic.Int64
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("console.log('cdn');"))
	}))
	t.Cleanup(cdn.Close)
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><script src="%s/lib.js"></script></html>`, cdn.URL)
	}))
	t.Cleanup(home.Close)
	w := newWsp(t)
	writeWebConfig(t, w, home.URL+"/")
	code, _, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "allowed_hosts") || !strings.Contains(errs, "shop") {
		t.Fatalf("init = %d\n%s", code, errs)
	}
	if fileExists(w.base) {
		t.Error("a baseline was written")
	}
	if hits.Load() != 0 {
		t.Errorf("the cdn was contacted %d times", hits.Load())
	}
}

// Some scripts read and some not: init and accept warn with the count, and
// every check says so in the report without calling the check incomplete.
func TestWebSomeScriptsUnreadIsNoted(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("console.log('cdn');"))
	}))
	t.Cleanup(cdn.Close)
	var mu sync.Mutex
	own := "console.log('own');"
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/own.js" {
			mu.Lock()
			defer mu.Unlock()
			_, _ = w.Write([]byte(own))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><script src="/own.js"></script><script src="%s/a.js?k=%s"></script><script src="%s/b.js"></script></html>`, cdn.URL, d1Token, cdn.URL)
	}))
	t.Cleanup(home.Close)
	w := newWsp(t)
	writeWebConfig(t, w, home.URL+"/")

	code, _, errs := w.run("init")
	if code != 0 || !strings.Contains(errs, "2개") || !strings.Contains(errs, "allowed_hosts") {
		t.Fatalf("init = %d\n%s", code, errs)
	}
	for _, format := range []string{"md", "json"} {
		code, out, errs := w.run("check", "--format", format)
		if code != 0 {
			t.Fatalf("check %s = %d\n%s\n%s", format, code, out, errs)
		}
		if !strings.Contains(out, "2개") || !strings.Contains(out, "allowed_hosts") {
			t.Errorf("check %s has no note about unread scripts:\n%s", format, out)
		}
		if strings.Contains(out, "일부 점검을 하지 못했습니다") {
			t.Errorf("check %s shows the incomplete-check banner:\n%s", format, out)
		}
		if strings.Contains(out+errs, d1Token) || strings.Contains(out+errs, cdn.URL) {
			t.Errorf("check %s shows an address:\n%s", format, out)
		}
	}
	mu.Lock()
	own = "console.log('own v2');"
	mu.Unlock()
	code, out, errs := w.run("accept", "shop", "--note", "배포 승인")
	if code != 0 || !strings.Contains(errs, "2개") {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
}
