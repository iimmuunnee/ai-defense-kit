package watch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebScriptCap(t *testing.T) {
	var requests atomic.Int64
	srcs := make([]string, 0, 400)
	for i := range 400 {
		srcs = append(srcs, fmt.Sprintf("/s%d.js", i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page(srcs...))
			return
		}
		requests.Add(1)
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	obs, err := NewWebObserver(false).Observe(context.Background(), webTarget(map[string]any{"url": srv.URL + "/"}))
	var pe PartialError
	if obs != nil || !errors.As(err, &pe) {
		t.Fatalf("obs=%d fields, err=%v", len(obs), err)
	}
	if got := requests.Load(); got > webMaxScripts {
		t.Errorf("%d script requests, cap is %d", got, webMaxScripts)
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "200") {
		t.Errorf("the error does not name the count: %v", err)
	}
	if n := countPrefix(pe.Obs, "script:"); n != webMaxScripts {
		t.Errorf("%d fields read, want %d", n, webMaxScripts)
	}
}

func countPrefix(obs Observation, prefix string) int {
	n := 0
	for k := range obs {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// The scripts the user named are read first: a page cannot push them out.
func TestWebScriptCapReadsExtraScriptsFirst(t *testing.T) {
	srcs := make([]string, 0, webMaxScripts+1)
	for i := range webMaxScripts + 1 {
		srcs = append(srcs, fmt.Sprintf("/s%d.js", i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page(srcs...))
			return
		}
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	_, err := NewWebObserver(false).Observe(context.Background(), webTarget(map[string]any{"url": srv.URL + "/", "extra_scripts": []any{srv.URL + "/mine.js"}}))
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if pe.Obs["script:"+srv.URL+"/mine.js"] == "" {
		t.Error("an extra script was pushed out by the page's own scripts")
	}
}

// A field holds every script with that path. One cut off must not leave a value
// made from only some of them, which would read as a change.
func TestWebScriptCapLeavesNoHalfField(t *testing.T) {
	srcs := make([]string, 0, webMaxScripts+5)
	for i := range webMaxScripts + 5 {
		srcs = append(srcs, fmt.Sprintf("/same.js?v=%d", i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page(srcs...))
			return
		}
		fmt.Fprint(w, r.URL.RawQuery)
	}))
	defer srv.Close()
	_, err := NewWebObserver(false).Observe(context.Background(), webTarget(map[string]any{"url": srv.URL + "/"}))
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if v, has := pe.Obs["script:"+srv.URL+"/same.js"]; has {
		t.Errorf("a field read in part was recorded: %s", v)
	}
}

// Up to the cap nothing changes.
func TestWebScriptCapExactlyAtTheLimit(t *testing.T) {
	srcs := make([]string, 0, webMaxScripts)
	for i := range webMaxScripts {
		srcs = append(srcs, fmt.Sprintf("/s%d.js", i))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page(srcs...))
			return
		}
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	obs, err := NewWebObserver(false).Observe(context.Background(), webTarget(map[string]any{"url": srv.URL + "/"}))
	if err != nil || countPrefix(obs, "script:") != webMaxScripts {
		t.Errorf("err=%v fields=%d", err, countPrefix(obs, "script:"))
	}
}

// A page that keeps answering until the deadline: what was read so far is kept.
func TestWebDeadlineKeepsWhatWasRead(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, page("/a.js", "/hang.js"))
		case "/a.js":
			fmt.Fprint(w, "a")
		default:
			<-stop
		}
	}))
	defer srv.Close()
	defer close(stop)
	tctx, tcancel := context.WithTimeout(context.Background(), time.Second)
	defer tcancel()
	_, err := NewWebObserver(false).Observe(tctx, webTarget(map[string]any{"url": srv.URL + "/"}))
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if pe.Obs["script:"+srv.URL+"/a.js"] != sum("a") {
		t.Errorf("partial = %v", pe.Obs)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v does not say the deadline passed", err)
	}
}
