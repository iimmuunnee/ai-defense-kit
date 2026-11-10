package ctlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "assets", "crtsh", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noWait(int) time.Duration { return 0 }

func jsonServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func checkEntries(t *testing.T, got []Entry) {
	t.Helper()
	if len(got) != 3 {
		t.Fatalf("항목 수 = %d, 기대 3", len(got))
	}
	if got[0].NameValue != "example.test\nwww.example.test" || got[0].ID != 29824981846 || got[0].ResultCount != 2 {
		t.Errorf("첫 항목이 다름: %+v", got[0])
	}
	if want := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC); !got[0].NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, 기대 %v", got[0].NotBefore, want)
	}
	if want := time.Date(2027, 1, 11, 23, 59, 59, 0, time.UTC); !got[0].NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, 기대 %v", got[0].NotAfter, want)
	}
	if got[0].NotBefore.Location() != time.UTC || got[0].NotAfter.Location() != time.UTC {
		t.Errorf("시간대 없는 날짜는 UTC로 읽어야 함: %v %v", got[0].NotBefore.Location(), got[0].NotAfter.Location())
	}
	if got[1].NameValue != "*.example.test\nexample.test" || got[2].NameValue != "api.example.test" {
		t.Errorf("이름이 다름: %+v", got)
	}
}

func TestFetchParsesEntries(t *testing.T) {
	for _, name := range []string{"sample.json", "sample_upper.json"} {
		t.Run(name, func(t *testing.T) {
			srv := jsonServer(t, fixture(t, name))
			got, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
			if err != nil {
				t.Fatal(err)
			}
			checkEntries(t, got)
		})
	}
}

func TestFetchQuery(t *testing.T) {
	var q map[string][]string
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		ua = r.UserAgent()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	check := func(exclude bool) {
		q = nil
		_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, UserAgent: "adk-test/1.0", ExcludeExpired: exclude, Backoff: noWait})
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range map[string]string{"dNSName": "example.test", "match": "ILIKE", "deduplicate": "Y", "output": "json"} {
			if len(q[k]) != 1 || q[k][0] != v {
				t.Errorf("%s = %v, 기대 %s", k, q[k], v)
			}
		}
		if got := len(q["exclude"]) == 1 && q["exclude"][0] == "expired"; got != exclude {
			t.Errorf("exclude = %v, ExcludeExpired=%v", q["exclude"], exclude)
		}
		if ua != "adk-test/1.0" {
			t.Errorf("User-Agent = %q", ua)
		}
	}
	check(false)
	check(true)
}

func TestFetchRejectsBadDomain(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	for _, d := range []string{"", "   ", "%.example.test", "a%25b.example.test"} {
		if _, err := Fetch(context.Background(), d, Options{BaseURL: srv.URL, Backoff: noWait}); err == nil {
			t.Errorf("%q: 오류가 나야 함", d)
		}
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("잘못된 도메인인데 요청이 %d번 나감", hits)
	}
}

func TestFetchQueryEscapesDomain(t *testing.T) {
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), "a.example.test&exclude=expired", Options{BaseURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "&exclude=expired") {
		t.Errorf("도메인이 질의 문자열에 끼어들었음: %s", raw)
	}
}

func TestFetchHTMLErrorFails(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte("<HTML><BODY>Unsupported output type</BODY></HTML>"))
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil {
		t.Fatal("오류가 나야 함")
	}
	if !strings.Contains(err.Error(), "crt.sh 조회에 실패했습니다") || !strings.Contains(err.Error(), "crt.sh가 JSON 대신 오류 페이지를 돌려줬습니다") {
		t.Errorf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("시도 횟수 = %d, 기대 3", hits)
	}
}

func TestFetchJSONContentTypeIsCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Application/JSON;charset=UTF-8")
		w.Write(fixture(t, "sample.json"))
	}))
	defer srv.Close()
	got, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err != nil {
		t.Fatal(err)
	}
	checkEntries(t, got)
}

func TestFetch5xxRetriesThenSucceeds(t *testing.T) {
	var hits int32
	body := fixture(t, "sample.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	got, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err != nil {
		t.Fatal(err)
	}
	checkEntries(t, got)
	if atomic.LoadInt32(&hits) != 2 {
		t.Errorf("시도 횟수 = %d, 기대 2", hits)
	}
}

func TestFetch429Retries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Errorf("시도 횟수 = %d, 기대 2", hits)
	}
}

func TestFetch4xxDoesNotRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "crt.sh 조회에 실패했습니다") {
		t.Fatalf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("시도 횟수 = %d, 기대 1", hits)
	}
}

func TestFetch5xxExhaustsAttempts(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait}); err == nil {
		t.Fatal("오류가 나야 함")
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("시도 횟수 = %d, 기대 3", hits)
	}
}

func TestFetchConnectionErrorRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // 연결 거부
	var waits int32
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: url, Backoff: func(int) time.Duration { atomic.AddInt32(&waits, 1); return 0 }})
	if err == nil || !strings.Contains(err.Error(), "crt.sh 조회에 실패했습니다") {
		t.Fatalf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&waits) != 2 {
		t.Errorf("대기 횟수 = %d, 기대 2", waits)
	}
}

func TestFetchTruncatedJSONFails(t *testing.T) {
	var hits int32
	srv := countingJSON(t, []byte(`[{"name_value":"a.example.test","id":1,"not_be`), &hits)
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "crt.sh 조회에 실패했습니다") {
		t.Fatalf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("시도 횟수 = %d, 기대 1", hits)
	}
}

func countingJSON(t *testing.T, body []byte, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchNotAnArrayFails(t *testing.T) {
	srv := jsonServer(t, []byte(`{"error":"x"}`))
	if _, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait}); err == nil {
		t.Fatal("오류가 나야 함")
	}
}

func TestFetchEmptyArrayIsOK(t *testing.T) {
	srv := jsonServer(t, fixture(t, "empty.json"))
	got, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("항목 수 = %d", len(got))
	}
}

func TestFetchBodyTooLargeFails(t *testing.T) {
	old := maxBodyBytes
	maxBodyBytes = 64
	defer func() { maxBodyBytes = old }()
	srv := jsonServer(t, fixture(t, "sample.json"))
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "크기") {
		t.Fatalf("오류 문구: %v", err)
	}
}

func TestFetchBadDatesBecomeZero(t *testing.T) {
	srv := jsonServer(t, []byte(`[{"name_value":"a.example.test","id":1,"not_before":"2026-01-10 01:02:03","not_after":"garbage"}]`))
	got, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 1, 10, 1, 2, 3, 0, time.UTC); !got[0].NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v", got[0].NotBefore)
	}
	if !got[0].NotAfter.IsZero() {
		t.Errorf("NotAfter = %v, 0값이어야 함", got[0].NotAfter)
	}
}

func TestFetchContextCancel(t *testing.T) {
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	done := make(chan error, 1)
	go func() {
		_, err := Fetch(ctx, "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("오류가 나야 함")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("취소 후에도 돌아오지 않음")
	}
}

func TestFetchBackoffWaitHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Fetch(ctx, "example.test", Options{BaseURL: srv.URL, Backoff: func(int) time.Duration { return time.Hour }})
	if err == nil {
		t.Fatal("오류가 나야 함")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("대기가 ctx 취소를 따르지 않음")
	}
}

func TestTruncated(t *testing.T) {
	cases := []struct {
		name string
		in   []Entry
		want bool
	}{
		{"nil", nil, false},
		{"9999", []Entry{{ResultCount: 9999}}, false},
		{"정확히 10000", []Entry{{ResultCount: 10000}}, true},
		{"합이 10000", []Entry{{ResultCount: 6000}, {ResultCount: 4000}}, true},
		{"합이 모자람", []Entry{{ResultCount: 6000}, {ResultCount: 3999}}, false},
	}
	for _, c := range cases {
		if got := Truncated(c.in); got != c.want {
			t.Errorf("%s: %v, 기대 %v", c.name, got, c.want)
		}
	}
}

func TestFetchNullAndNonArrayFail(t *testing.T) {
	for _, b := range []string{"null", `"x"`, "42", `{"a":1}`} {
		srv := jsonServer(t, []byte(b))
		if _, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait}); err == nil {
			t.Errorf("%s: 오류가 나야 함", b)
		}
	}
}

func TestFetchTrimsDomain(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("dNSName")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), "  example.test \n", Options{BaseURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if got != "example.test" {
		t.Errorf("dnsname = %q", got)
	}
}

func TestFetchNonJSONContentTypeShownInError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hi"))
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "text/plain") || !strings.Contains(err.Error(), "JSON 대신 오류 페이지") {
		t.Fatalf("오류 문구: %v", err)
	}
}

func TestFetchTimeoutRetries(t *testing.T) {
	old := requestTimeout
	requestTimeout = 50 * time.Millisecond
	defer func() { requestTimeout = old }()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "crt.sh 조회에 실패했습니다") {
		t.Fatalf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("시도 횟수 = %d, 기대 3 (시간 초과는 재시도)", hits)
	}
}

func TestFetchRedirectToOtherHostFails(t *testing.T) {
	var otherHits, hits int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer other.Close()
	// 127.0.0.1 대신 localhost로 보내 호스트 이름이 달라지게 한다.
	target := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL, Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "리다이렉트") || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 || atomic.LoadInt32(&otherHits) != 0 {
		t.Errorf("hits=%d otherHits=%d, 기대 1/0 (재시도 없음, 다른 호스트 접속 없음)", hits, otherHits)
	}
}

func TestFetchRedirectHTTPSDowngradeFails(t *testing.T) {
	var plainHits int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&plainHits, 1)
	}))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tls.Close()
	_, err := Fetch(context.Background(), "example.test", Options{BaseURL: tls.URL, HTTPClient: tls.Client(), Backoff: noWait})
	if err == nil || !strings.Contains(err.Error(), "리다이렉트") {
		t.Fatalf("오류 문구: %v", err)
	}
	if atomic.LoadInt32(&plainHits) != 0 {
		t.Errorf("https에서 http로 내려갔음")
	}
}

func TestFetchRedirectSameHostHTTPSAllowed(t *testing.T) {
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture(t, "sample.json"))
	}))
	defer secure.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secure.URL+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))
	defer plain.Close()
	orig := secure.Client()
	got, err := Fetch(context.Background(), "example.test", Options{BaseURL: plain.URL, HTTPClient: orig, Backoff: noWait})
	if err != nil {
		t.Fatal(err)
	}
	checkEntries(t, got)
	if orig.CheckRedirect != nil {
		t.Error("넘겨받은 클라이언트를 바꾸면 안 됨")
	}
}

func TestFetchQueryParamNameIsCaseSensitive(t *testing.T) {
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), "example.test", Options{BaseURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "dNSName=example.test") || strings.Contains(raw, "dnsname=") {
		t.Errorf("질의 = %s", raw)
	}
}
