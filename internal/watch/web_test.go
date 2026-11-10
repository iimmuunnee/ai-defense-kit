package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func page(srcs ...string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><title>t</title>")
	for _, s := range srcs {
		fmt.Fprintf(&b, `<script src="%s"></script>`, s)
	}
	b.WriteString("</head><body><script>var inline=1;</script></body></html>")
	return b.String()
}

// site serves fixed bodies by path. Paths not listed answer 404.
type site struct {
	srv  *httptest.Server
	body map[string]string
	hits atomic.Int64
}

func newSite(t *testing.T, body map[string]string) *site {
	t.Helper()
	s := &site{body: body}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		b, ok := s.body[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "text/javascript")
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func webTarget(opts map[string]any) Target {
	return Target{Key: "site", Kind: kindWeb, Options: opts}
}

func observeWeb(t *testing.T, opts map[string]any) (Observation, error) {
	t.Helper()
	return NewWebObserver(false).Observe(context.Background(), webTarget(opts))
}

func TestWebHashes(t *testing.T) {
	s := newSite(t, map[string]string{
		"/a.js":     "console.log('a');",
		"/sub/b.js": "console.log('b');",
		"/c.js":     "console.log('c');",
		"/extra.js": "console.log('x');",
	})
	host := strings.TrimPrefix(s.srv.URL, "http://")
	s.body["/"] = page("/a.js?v=123#frag", "sub/b.js", "//"+host+"/c.js")
	obs, err := observeWeb(t, map[string]any{"url": s.srv.URL + "/?utm=1#top", "extra_scripts": []any{s.srv.URL + "/extra.js?x=1"}})
	if err != nil {
		t.Fatal(err)
	}
	want := Observation{
		"url":                               s.srv.URL + "/",
		"script:" + s.srv.URL + "/a.js":     sum("console.log('a');"),
		"script:" + s.srv.URL + "/sub/b.js": sum("console.log('b');"),
		"script:" + s.srv.URL + "/c.js":     sum("console.log('c');"),
		"script:" + s.srv.URL + "/extra.js": sum("console.log('x');"),
	}
	if len(obs) != len(want) {
		t.Fatalf("obs = %v\nwant %v", obs, want)
	}
	for k, v := range want {
		if obs[k] != v {
			t.Errorf("%s = %q, want %q", k, obs[k], v)
		}
	}
	// A cache buster does not change the field.
	s.body["/"] = strings.ReplaceAll(s.body["/"], "v=123", "v=999")
	again, err := observeWeb(t, map[string]any{"url": s.srv.URL + "/", "extra_scripts": []any{s.srv.URL + "/extra.js"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff("site", obs, again); len(d) != 0 {
		t.Errorf("cache buster changed fields: %v", d)
	}
	// A changed script is a change of its own field only.
	s.body["/a.js"] = "console.log('a2');"
	changed, _ := observeWeb(t, map[string]any{"url": s.srv.URL + "/", "extra_scripts": []any{s.srv.URL + "/extra.js"}})
	d := Diff("site", obs, changed)
	if len(d) != 1 || d[0].Field != "script:"+s.srv.URL+"/a.js" {
		t.Errorf("diff = %v", d)
	}
}

func TestWebTransient(t *testing.T) {
	big := strings.Repeat("a", webMaxBody+1)
	exact := strings.Repeat("b", webMaxBody)
	bodies := map[string]string{
		"/":         page("/ok.js", "/bad.js"),
		"/ok.js":    "ok",
		"/big.js":   big,
		"/exact.js": exact,
		"/withbig":  page("/big.js", "/ok.js"),
		"/exact":    page("/exact.js"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/5xx":
			http.Error(w, "boom", 500)
		case "/bad.js":
			http.Error(w, "boom", 503)
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("<script src=/ok.js></script>"))
		case "/nocontenttype":
			w.Header()["Content-Type"] = nil
			_, _ = w.Write([]byte("<script src=/ok.js></script>"))
		case "/bightml":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(big))
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/out":
			http.Redirect(w, r, "http://other.invalid/x?token=SECRETTOKEN", http.StatusFound)
		case "/outscript":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/jump.js", "/ok.js")))
		case "/jump.js":
			http.Redirect(w, r, "http://other.invalid/x.js?token=SECRETTOKEN", http.StatusFound)
		case "/inredirect":
			http.Redirect(w, r, "/", http.StatusFound)
		default:
			b, ok := bodies[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if strings.HasSuffix(r.URL.Path, ".js") {
				w.Header().Set("Content-Type", "text/javascript")
			} else {
				w.Header().Set("Content-Type", "text/html")
			}
			_, _ = w.Write([]byte(b))
		}
	}))
	t.Cleanup(srv.Close)
	u := func(p string) map[string]any { return map[string]any{"url": srv.URL + p} }

	var pe PartialError
	for _, tc := range []struct{ name, path string }{
		{"5xx", "/5xx"}, {"404", "/missing"}, {"outside redirect", "/out"}, {"loop", "/loop"},
		{"over limit page", "/bightml"}, {"non-html", "/text"}, {"no content type", "/nocontenttype"},
	} {
		obs, err := observeWeb(t, u(tc.path))
		if err == nil || obs != nil {
			t.Errorf("%s: obs=%v err=%v", tc.name, obs, err)
			continue
		}
		if errors.As(err, &pe) {
			t.Errorf("%s: a failed page must be a plain error, got PartialError", tc.name)
		}
		if strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), "other.invalid") {
			t.Errorf("%s: error holds a URL: %v", tc.name, err)
		}
	}

	// A redirect inside the allowed host is followed.
	// "/" lists /bad.js, so the result is partial: ok.js must have been read.
	obs0, err0 := observeWeb(t, u("/inredirect"))
	if !errors.As(err0, &pe) || obs0 != nil || pe.Obs["script:"+srv.URL+"/ok.js"] != sum("ok") {
		t.Errorf("inside redirect: obs=%v err=%v", obs0, err0)
	}

	// A script that fails after the page was read is a PartialError that keeps what was read.
	obs, err := observeWeb(t, u("/"))
	if !errors.As(err, &pe) || obs != nil {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	if pe.Obs["script:"+srv.URL+"/ok.js"] != sum("ok") || pe.Obs["url"] != srv.URL+"/" {
		t.Errorf("partial obs = %v", pe.Obs)
	}
	if _, bad := pe.Obs["script:"+srv.URL+"/bad.js"]; bad {
		t.Error("a script that failed must not appear as a field")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error does not say why: %v", err)
	}

	// A script redirected outside the allowed hosts, and one over the limit, are partial too.
	_, err = observeWeb(t, u("/outscript"))
	if !errors.As(err, &pe) || strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), "other.invalid") {
		t.Errorf("outscript: %v", err)
	}
	_, err = observeWeb(t, u("/withbig"))
	if !errors.As(err, &pe) || pe.Obs["script:"+srv.URL+"/ok.js"] != sum("ok") {
		t.Errorf("withbig: err=%v pe=%v", err, pe.Obs)
	}
	if _, has := pe.Obs["script:"+srv.URL+"/big.js"]; has {
		t.Error("over-limit script was recorded")
	}

	// Exactly at the limit is read.
	if obs, err := observeWeb(t, u("/exact")); err != nil || obs["script:"+srv.URL+"/exact.js"] != sum(exact) {
		t.Errorf("exact limit: err=%v", err)
	}
}

func TestWebExternalScriptsAreNotFetched(t *testing.T) {
	other := newSite(t, map[string]string{"/lib.js": "external"})
	home := newSite(t, nil)
	home.body = map[string]string{"/": page(other.srv.URL+"/lib.js?k=SECRETKEY", "/own.js"), "/own.js": "own"}
	opts := map[string]any{"url": home.srv.URL + "/"}
	obs, err := observeWeb(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	if other.hits.Load() != 0 {
		t.Errorf("a script on an unlisted host was fetched (%d hits)", other.hits.Load())
	}
	f := "script:" + other.srv.URL + "/lib.js"
	if obs[f] != "not-fetched" {
		t.Errorf("%s = %q", f, obs[f])
	}
	for k, v := range obs {
		if strings.Contains(k+v, "SECRETKEY") {
			t.Errorf("query reached the observation: %s=%s", k, v)
		}
	}
	// A new external script reads as a change.
	home.body["/"] = page("/own.js")
	obs2, _ := observeWeb(t, opts)
	if d := Diff("site", obs, obs2); len(d) != 1 || d[0].Field != f || d[0].Old != "not-fetched" || d[0].New != "" {
		t.Errorf("diff = %v", d)
	}

	// Listing the host makes it fetched.
	home.body["/"] = page(other.srv.URL + "/lib.js")
	opts["allowed_hosts"] = []any{strings.TrimPrefix(other.srv.URL, "http://")}
	obs3, err := observeWeb(t, opts)
	if err != nil || obs3[f] != sum("external") {
		t.Errorf("allowed host: obs=%v err=%v", obs3, err)
	}
	// The allowed host is matched with its port: the same name on another port is another host.
	opts["allowed_hosts"] = []any{"127.0.0.1:1"}
	obs4, _ := observeWeb(t, opts)
	if obs4[f] != "not-fetched" {
		t.Errorf("port ignored: %v", obs4)
	}
}

func TestWebExtraScriptsOnUnlistedHostAreOptionErrors(t *testing.T) {
	other := newSite(t, map[string]string{"/x.js": "x"})
	home := newSite(t, map[string]string{"/": page("/own.js"), "/own.js": "own"})
	_, err := observeWeb(t, map[string]any{"url": home.srv.URL + "/", "extra_scripts": []any{other.srv.URL + "/x.js?t=SECRETTOKEN"}})
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") || other.hits.Load() != 0 {
		t.Errorf("err=%v hits=%d", err, other.hits.Load())
	}
	if err := validateWebOptions(map[string]any{"url": "https://example.com/", "extra_scripts": []any{"https://cdn.example.org/x.js"}}); err == nil {
		t.Error("extra_scripts on an unlisted host passed validation")
	}
	if err := validateWebOptions(map[string]any{"url": "https://example.com/", "extra_scripts": []any{"https://cdn.example.org/x.js"}, "allowed_hosts": []any{"CDN.example.org"}}); err != nil {
		t.Errorf("listed host (case-insensitive) rejected: %v", err)
	}
	// No suffix matching.
	if err := validateWebOptions(map[string]any{"url": "https://example.com/", "extra_scripts": []any{"https://a.cdn.example.org/x.js"}, "allowed_hosts": []any{"cdn.example.org"}}); err == nil {
		t.Error("suffix matched")
	}
}

func TestWebOptionErrorsDoNotEchoSecrets(t *testing.T) {
	for name, opts := range map[string]map[string]any{
		"userinfo in url":     {"url": "https://admin:SECRETPW@example.com/"},
		"userinfo in extra":   {"url": "https://example.com/", "extra_scripts": []any{"https://u:SECRETPW@example.com/a.js"}},
		"bad scheme":          {"url": "ftp://example.com/SECRETPW"},
		"no url":              {},
		"url not text":        {"url": 5},
		"unknown option":      {"url": "https://example.com/", "allowed_host": []any{"x"}},
		"extra not list":      {"url": "https://example.com/", "extra_scripts": "https://example.com/a.js?t=SECRETPW"},
		"relative extra":      {"url": "https://example.com/", "extra_scripts": []any{"a.js?t=SECRETPW"}},
		"host with path":      {"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.org/SECRETPW"}},
		"host with userinfo":  {"url": "https://example.com/", "allowed_hosts": []any{"SECRETPW@cdn.example.org"}},
		"host not text":       {"url": "https://example.com/", "allowed_hosts": []any{5}},
		"empty allowed host":  {"url": "https://example.com/", "allowed_hosts": []any{""}},
		"missing host in url": {"url": "https:///SECRETPW"},
	} {
		err := validateWebOptions(opts)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "SECRETPW") {
			t.Errorf("%s: error echoes the value: %v", name, err)
		}
		if _, oerr := observeWeb(t, opts); oerr == nil || strings.Contains(oerr.Error(), "SECRETPW") {
			t.Errorf("%s: observe err = %v", name, oerr)
		}
	}
}

func TestWebSameNameScriptsCombineStably(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/a.js?v=1", "/a.js?v=2")))
		case "/rev":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/a.js?v=2", "/a.js?v=1")))
		case "/a.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte("content-" + r.URL.Query().Get("v")))
		}
	}))
	t.Cleanup(srv.Close)
	a, err := observeWeb(t, map[string]any{"url": srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := observeWeb(t, map[string]any{"url": srv.URL + "/rev"})
	if err != nil {
		t.Fatal(err)
	}
	f := "script:" + srv.URL + "/a.js"
	if a[f] == "" || a[f] != b[f] {
		t.Errorf("order changed the value: %q vs %q", a[f], b[f])
	}
	if a[f] == sum("content-1") || a[f] == sum("content-2") {
		t.Errorf("one of the two was dropped")
	}
	if len(a) != 2 {
		t.Errorf("obs = %v", a)
	}
}

func TestWebAllScriptsGoneIsChanges(t *testing.T) {
	s := newSite(t, map[string]string{"/": page("/a.js", "/b.js"), "/a.js": "a", "/b.js": "b"})
	opts := map[string]any{"url": s.srv.URL + "/"}
	base, err := observeWeb(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	s.body["/"] = "<html><body>maintenance</body></html>"
	now, err := observeWeb(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff("site", base, now); len(d) != 2 {
		t.Errorf("diff = %v", d)
	}
	if err := CheckInitial(webTarget(opts), now); err == nil {
		t.Error("a page with no scripts passed CheckInitial")
	}
	if err := CheckInitial(webTarget(opts), base); err != nil {
		t.Errorf("CheckInitial(base) = %v", err)
	}
	withExtra := Observation{"url": "x", "script:http://h/e.js": "abc"}
	if err := CheckInitial(webTarget(map[string]any{"url": "http://h/"}), withExtra); err != nil {
		t.Errorf("CheckInitial with a script = %v", err)
	}
}

func TestWebURLIdentityWithoutQueryOrFragment(t *testing.T) {
	s := newSite(t, map[string]string{"/p": page("/a.js"), "/a.js": "a"})
	obs, err := observeWeb(t, map[string]any{"url": s.srv.URL + "/p?token=SECRETTOKEN#x"})
	if err != nil {
		t.Fatal(err)
	}
	if obs["url"] != s.srv.URL+"/p" {
		t.Errorf("url = %q", obs["url"])
	}
	for k, v := range obs {
		if strings.Contains(k+v, "SECRETTOKEN") {
			t.Errorf("token leaked: %s=%s", k, v)
		}
	}
}

func TestWebHostCaseIsIgnored(t *testing.T) {
	var port string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("http://LOCALHOST:" + port + "/a.js")))
			return
		}
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write([]byte("a"))
	}))
	t.Cleanup(srv.Close)
	port = strings.Split(srv.URL, ":")[2]
	obs, err := observeWeb(t, map[string]any{"url": "http://localhost:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if obs["script:http://localhost:"+port+"/a.js"] != sum("a") {
		t.Errorf("obs = %v", obs)
	}
}

func TestWebCancelledContextIsAnError(t *testing.T) {
	s := newSite(t, map[string]string{"/": page("/a.js"), "/a.js": "a"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	obs, err := NewWebObserver(false).Observe(ctx, webTarget(map[string]any{"url": s.srv.URL + "/"}))
	if err == nil || obs != nil {
		t.Errorf("obs=%v err=%v", obs, err)
	}
}

func TestLoadConfigNewKinds(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "w.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := "targets:\n  - key: site\n    kind: web-scripts\n    options:\n      url: \"https://example.com/\"\n  - key: repo\n    kind: repo-files\n    options:\n      root: \".\"\n"
	if _, err := LoadConfig(write(ok)); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, body := range map[string]string{
		"web unknown option":  "targets:\n  - key: a\n    kind: web-scripts\n    options:\n      url: \"https://example.com/\"\n      roots: x\n",
		"web userinfo":        "targets:\n  - key: a\n    kind: web-scripts\n    options:\n      url: \"https://u:SECRETPW@example.com/\"\n",
		"repo unknown option": "targets:\n  - key: a\n    kind: repo-files\n    options:\n      root: \".\"\n      glob: x\n",
		"repo bad glob":       "targets:\n  - key: a\n    kind: repo-files\n    options:\n      root: \".\"\n      globs: [\"[\"]\n",
		"repo no root":        "targets:\n  - key: a\n    kind: repo-files\n    options:\n      globs: [\"*\"]\n",
	} {
		_, err := LoadConfig(write(body))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "SECRETPW") {
			t.Errorf("%s: echoed: %v", name, err)
		}
	}
}

func TestClassifyNewKinds(t *testing.T) {
	for _, tc := range []struct{ kind, field, id string }{
		{kindWeb, "script:https://x/a.js", "WA-101"},
		{kindRepo, "file:.github/workflows/ci.yml", "WA-102"},
		{kindWeb, "url", "WA-007"},
		{kindRepo, "root", "WA-007"},
	} {
		id, sev, _, _ := classify(tc.kind, Change{Field: tc.field}, nil)
		if id != tc.id || sev.String() != "high" {
			t.Errorf("%s -> %s %s", tc.field, id, sev)
		}
	}
	if SingleEndpoint(Target{Kind: kindWeb}) || PlainHTTPEndpoints(Target{Kind: kindRepo}) != nil {
		t.Error("evm-only notes leak into the new kinds")
	}
}

// The limits of the two newer kinds are in the document, and the document
// says not to put a secret in the page address.
func TestWatchDocsNewKinds(t *testing.T) {
	s := readText(t, "../../docs/watch.md")
	for _, want := range []string{
		"`web-scripts`", "`repo-files`", "`allowed_hosts`", "`extra_scripts`", "`not-fetched`",
		"WA-101", "WA-102", "인라인", "방문자", "점검 사이", "해시가 붙는", "`TestDrillD1`",
		"설정 파일에 적는 주소에는 비밀", "`Referer`", "`import()`", "`cdn.example.com:443`", "사라진 항목에는 `--expect`", "심볼릭 링크", "5MiB", "`**`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
	for _, bad := range []string{"막는다", "안전", "방어한다"} {
		if strings.Contains(s, bad) {
			t.Errorf("docs/watch.md contains %q", bad)
		}
	}
	for _, f := range []string{"../../explain/WA-101.md", "../../explain/WA-102.md", "../../fixes/WA-101/watch.md", "../../fixes/WA-102/watch.md"} {
		text := readText(t, f)
		for _, bad := range []string{"막는다", "안전", "방어한다"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
	for _, f := range []string{"../../explain/WA-101.md", "../../explain/WA-102.md"} {
		text := readText(t, f)
		for _, want := range []string{"adk watch accept", "--expect", "정상"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %q", f, want)
			}
		}
	}
}
