package watch

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// chainSite serves /chain/<n>/<dest>: n redirects, then dest ("pageA" lists a
// script behind 5 redirects, "pageB" one behind 6, "pageC" a relative script,
// anything else is a script).
func chainSite(t *testing.T, seen func(*http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen(r)
		}
		var n int
		var dest string
		if _, err := fmt.Sscanf(r.URL.Path, "/chain/%d/%s", &n, &dest); err != nil {
			http.NotFound(w, r)
			return
		}
		if n > 0 {
			http.Redirect(w, r, fmt.Sprintf("/chain/%d/%s", n-1, dest), http.StatusFound)
			return
		}
		switch dest {
		case "pageA":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/chain/5/js")))
		case "pageB":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/chain/6/js")))
		case "pageC":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/chain/0/js")))
		default:
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write([]byte("js-ok"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWebRedirectsAreFollowedUpToFive(t *testing.T) {
	srv := chainSite(t, nil)
	// The page behind 5 redirects and its script behind 5 redirects are read.
	obs, err := observeWeb(t, map[string]any{"url": srv.URL + "/chain/5/pageA"})
	if err != nil {
		t.Fatalf("5 redirects: %v", err)
	}
	if obs["script:"+srv.URL+"/chain/5/js"] != sum("js-ok") {
		t.Errorf("obs = %v", obs)
	}
	// The 6th redirect of a page is an error, and a plain one.
	var pe PartialError
	if o, err := observeWeb(t, map[string]any{"url": srv.URL + "/chain/6/pageA"}); err == nil || o != nil || errors.As(err, &pe) {
		t.Errorf("6 redirects of the page: obs=%v err=%v", o, err)
	}
	// The 6th redirect of a script leaves a PartialError that keeps the page's own fields.
	_, err = observeWeb(t, map[string]any{"url": srv.URL + "/chain/5/pageB"})
	if !errors.As(err, &pe) {
		t.Fatalf("6 redirects of a script: %v", err)
	}
	if _, has := pe.Obs["script:"+srv.URL+"/chain/6/js"]; has || pe.Obs["url"] == "" {
		t.Errorf("partial = %v", pe.Obs)
	}
}

func TestWebRedirectToAllowedHost(t *testing.T) {
	var refs []string
	var mu sync.Mutex
	other := chainSite(t, func(r *http.Request) {
		mu.Lock()
		refs = append(refs, r.Header.Get("Referer"))
		mu.Unlock()
	})
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Referer"); got != "" {
			t.Errorf("Referer sent to the page host: %q", got)
		}
		switch r.URL.Path {
		case "/hop":
			http.Redirect(w, r, other.URL+"/chain/0/pageC", http.StatusFound)
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/jump.js")))
		case "/jump.js":
			http.Redirect(w, r, other.URL+"/chain/0/js", http.StatusFound)
		}
	}))
	t.Cleanup(home.Close)
	allowed := []any{strings.TrimPrefix(other.URL, "http://")}

	// Page redirected to the allowed host: its script resolves against the final URL and is read there.
	obs, err := observeWeb(t, map[string]any{"url": home.URL + "/hop?token=SECRETTOKEN", "allowed_hosts": allowed})
	if err != nil || obs["url"] != home.URL+"/hop" || obs["script:"+other.URL+"/chain/0/js"] != sum("js-ok") {
		t.Fatalf("page redirect: obs=%v err=%v", obs, err)
	}
	// A script redirected to the allowed host is read.
	obs, err = observeWeb(t, map[string]any{"url": home.URL + "/page?token=SECRETTOKEN", "allowed_hosts": allowed})
	if err != nil || obs["script:"+home.URL+"/jump.js"] != sum("js-ok") {
		t.Fatalf("script redirect: obs=%v err=%v", obs, err)
	}
	// Without the host listed the same redirect is refused.
	if _, err = observeWeb(t, map[string]any{"url": home.URL + "/hop"}); err == nil {
		t.Error("redirect to an unlisted host was followed")
	}
	// No request carried the page's address (and its token) as a Referer.
	mu.Lock()
	defer mu.Unlock()
	if len(refs) == 0 {
		t.Fatal("the other host was never reached")
	}
	for _, r := range refs {
		if r != "" {
			t.Errorf("Referer = %q", r)
		}
	}
}

func TestWebSchemeAndPortIdentity(t *testing.T) {
	u := func(s string) *url.URL {
		p, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name  string
		opts  map[string]any
		check string
		want  bool
	}{
		{"same origin", map[string]any{"url": "https://example.com/"}, "https://example.com/x.js", true},
		{"explicit default port", map[string]any{"url": "https://example.com/"}, "https://example.com:443/x.js", true},
		{"http is another origin than https", map[string]any{"url": "https://example.com/"}, "http://example.com/x.js", false},
		{"https is another origin than http", map[string]any{"url": "http://example.com/"}, "https://example.com/x.js", false},
		{"entry without port is the page scheme default", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com"}}, "https://cdn.example.com/x.js", true},
		{"entry without port, other scheme", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com"}}, "http://cdn.example.com/x.js", false},
		{"entry host:443 equals https", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com:443"}}, "https://cdn.example.com/x.js", true},
		{"entry host:443 is not http", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com:443"}}, "http://cdn.example.com/x.js", false},
		{"entry host:80 allows exactly that pair", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com:80"}}, "http://cdn.example.com/x.js", true},
		{"entry host:80 is not https", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com:80"}}, "https://cdn.example.com/x.js", false},
		{"other port on the page scheme", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com:8443"}}, "https://cdn.example.com:8443/x.js", true},
		{"other port, not listed", map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"cdn.example.com:8443"}}, "https://cdn.example.com/x.js", false},
		{"host case", map[string]any{"url": "https://Example.COM/"}, "https://example.com/x.js", true},
	} {
		w, err := parseWebOptions(tc.opts)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := w.allows(u(tc.check)); got != tc.want {
			t.Errorf("%s: allows(%s) = %v, want %v", tc.name, tc.check, got, tc.want)
		}
	}
	// extra_scripts follows the same rule.
	if err := validateWebOptions(map[string]any{"url": "https://example.com/", "extra_scripts": []any{"http://example.com/x.js"}}); err == nil {
		t.Error("an http extra script on an https page was accepted")
	}
	if err := validateWebOptions(map[string]any{"url": "https://example.com/", "extra_scripts": []any{"https://cdn.example.com/x.js"}, "allowed_hosts": []any{"cdn.example.com:443"}}); err != nil {
		t.Errorf("host:443 rejected: %v", err)
	}
}

func TestWebRedirectDowngradeIsRefused(t *testing.T) {
	w, err := parseWebOptions(map[string]any{"url": "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	c := (&webObserver{}).client(w)
	mk := func(s string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, s, nil)
		return r
	}
	via := []*http.Request{mk("https://example.com/")}
	if err := c.CheckRedirect(mk("http://example.com/x"), via); !errors.Is(err, errRedirectOutside) {
		t.Errorf("https to http = %v", err)
	}
	if err := c.CheckRedirect(mk("https://example.com/x"), via); err != nil {
		t.Errorf("same origin = %v", err)
	}
	w2, _ := parseWebOptions(map[string]any{"url": "https://example.com/", "allowed_hosts": []any{"example.com:80"}})
	c2 := (&webObserver{}).client(w2)
	if err := c2.CheckRedirect(mk("http://example.com/x"), via); err != nil {
		t.Errorf("listed pair = %v", err)
	}
	// A redirect never carries the page's address as a Referer.
	r := mk("https://example.com/x")
	r.Header.Set("Referer", "https://example.com/?token=SECRETTOKEN")
	if err := c.CheckRedirect(r, via); err != nil || r.Header.Get("Referer") != "" {
		t.Errorf("err=%v referer=%q", err, r.Header.Get("Referer"))
	}
}

func TestWebScriptOnOtherSchemeIsNotFetched(t *testing.T) {
	s := newSite(t, nil)
	port := strings.Split(s.srv.URL, ":")[2]
	s.body = map[string]string{"/": page("https://127.0.0.1:"+port+"/x.js", "/own.js"), "/own.js": "own"}
	obs, err := observeWeb(t, map[string]any{"url": s.srv.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if obs["script:https://127.0.0.1:"+port+"/x.js"] != notFetched {
		t.Errorf("obs = %v", obs)
	}
}

func TestWebNoRefererOnScriptFetches(t *testing.T) {
	var bad atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Referer") != "" {
			bad.Add(1)
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(page("/a.js")))
			return
		}
		_, _ = w.Write([]byte("a"))
	}))
	t.Cleanup(srv.Close)
	if _, err := observeWeb(t, map[string]any{"url": srv.URL + "/?token=SECRETTOKEN", "extra_scripts": []any{srv.URL + "/b.js"}}); err != nil {
		t.Fatal(err)
	}
	if bad.Load() != 0 {
		t.Errorf("%d requests carried a Referer", bad.Load())
	}
}

func TestWebUnreadScripts(t *testing.T) {
	obs := Observation{"url": "x", "script:https://a/x.js": notFetched, "script:https://a/y.js": "abc", "script:data:": "def"}
	if n := UnreadScripts(obs); n != 1 {
		t.Errorf("UnreadScripts = %d", n)
	}
	allOutside := Observation{"url": "x", "script:https://cdn/x.js": notFetched, "script:https://cdn/y.js": notFetched}
	err := CheckInitial(webTarget(map[string]any{"url": "https://h/"}), allOutside)
	if err == nil || !strings.Contains(err.Error(), "site") || !strings.Contains(err.Error(), "allowed_hosts") {
		t.Errorf("all not-fetched: %v", err)
	}
	if err := CheckInitial(webTarget(map[string]any{"url": "https://h/"}), obs); err != nil {
		t.Errorf("some read: %v", err)
	}
}
