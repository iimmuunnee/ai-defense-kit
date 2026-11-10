package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const secretKey = "SECRETKEY123"

func jsonServer(t *testing.T, result string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + result + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCallOK(t *testing.T) {
	srv := jsonServer(t, `"0x1"`)
	c := New([]string{srv.URL}, nil)
	got, err := c.Call(context.Background(), "eth_chainId", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"0x1"` {
		t.Fatalf("got %s", got)
	}
}

func TestNoURLs(t *testing.T) {
	c := New(nil, nil)
	if _, err := c.Call(context.Background(), "eth_chainId", nil); err == nil {
		t.Fatal("URL이 없으면 오류여야 합니다")
	}
	if _, _, err := c.Agreed(context.Background(), "eth_chainId", nil, 0); err == nil {
		t.Fatal("URL이 없으면 오류여야 합니다")
	}
}

func TestErrorsNeverContainURL(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // 연결 거부

	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom "+r.URL.Path, http.StatusInternalServerError)
	}))
	defer srv500.Close()
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>" + r.URL.Path + "</html>"))
	}))
	defer srvBad.Close()
	srvRPCErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}`))
	}))
	defer srvRPCErr.Close()

	for name, base := range map[string]string{
		"refused": deadURL, "500": srv500.URL, "badbody": srvBad.URL, "rpcerror": srvRPCErr.URL,
	} {
		u := base + "/v2/" + secretKey + "?apikey=" + secretKey
		c := New([]string{u}, nil)
		check := func(label string, err error) {
			if err == nil {
				t.Fatalf("%s/%s: 오류가 있어야 합니다", name, label)
			}
			msg := err.Error()
			host := strings.TrimPrefix(base, "http://")
			for _, bad := range []string{secretKey, host, "127.0.0.1", "http://", "/v2/"} {
				if strings.Contains(msg, bad) {
					t.Fatalf("%s/%s: 오류에 URL 일부 %q가 있습니다: %s", name, label, bad, msg)
				}
			}
		}
		_, err := c.Call(context.Background(), "eth_chainId", nil)
		check("call", err)
		_, _, err = c.Agreed(context.Background(), "eth_chainId", nil, 0)
		check("agreed", err)
		_, err = c.CallAll(context.Background(), "eth_chainId", nil)
		check("callall", err)
	}
}

func TestRefusesRedirect(t *testing.T) {
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/"+secretKey, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()

	for name, hc := range map[string]*http.Client{
		"nil":      nil,
		"injected": {Timeout: time.Second},
	} {
		c := New([]string{redir.URL}, hc)
		_, err := c.Call(context.Background(), "eth_chainId", nil)
		if err == nil {
			t.Fatalf("%s: 리다이렉트는 오류여야 합니다", name)
		}
		if strings.Contains(err.Error(), secretKey) {
			t.Fatalf("%s: 오류에 리다이렉트 주소가 있습니다", name)
		}
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("리다이렉트 대상에 %d번 접속했습니다", hits)
	}
}

func TestDoesNotMutateInjectedClient(t *testing.T) {
	hc := &http.Client{Timeout: time.Second}
	New([]string{"http://example.invalid"}, hc)
	if hc.CheckRedirect != nil {
		t.Fatal("호출자의 클라이언트를 바꾸면 안 됩니다")
	}
}

func TestResponseTooLarge(t *testing.T) {
	big := `"0x` + strings.Repeat("ab", 1<<20) + `"` // 2MiB
	srv := jsonServer(t, big)
	c := New([]string{srv.URL}, nil)
	_, err := c.Call(context.Background(), "eth_getCode", nil)
	if err == nil {
		t.Fatal("1MiB를 넘는 응답은 오류여야 합니다")
	}
}

func TestResponseNotHex(t *testing.T) {
	for _, res := range []string{`"hello"`, `"0xzz"`, `123`, `null`, `{"a":1}`} {
		srv := jsonServer(t, res)
		c := New([]string{srv.URL}, nil)
		if _, err := c.Call(context.Background(), "eth_chainId", nil); err == nil {
			t.Fatalf("결과 %s는 오류여야 합니다", res)
		}
	}
}

// 호출마다 순서대로 응답을 주고 호출 횟수를 센다.
func seqServer(t *testing.T, results ...string) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(atomic.AddInt32(&n, 1)) - 1
		if i >= len(results) {
			i = len(results) - 1
		}
		var req struct{ Method string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + results[i] + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestAgreedSingleURLIsOneCall(t *testing.T) {
	srv, n := seqServer(t, `"0xaa"`)
	c := New([]string{srv.URL}, nil)
	got, _, err := c.Agreed(context.Background(), "eth_getCode", nil, 0)
	if err != nil || string(got) != `"0xaa"` {
		t.Fatalf("got %s %v", got, err)
	}
	if *n != 1 {
		t.Fatalf("호출 %d번", *n)
	}
}

func TestAgreedIgnoresHexCase(t *testing.T) {
	a, _ := seqServer(t, `"0xABcd"`)
	b, _ := seqServer(t, `"0xabCD"`)
	c := New([]string{a.URL, b.URL}, nil)
	if _, _, err := c.Agreed(context.Background(), "eth_getCode", nil, 0); err != nil {
		t.Fatal(err)
	}
}

func TestAgreedDisagreeThenSettles(t *testing.T) {
	a, _ := seqServer(t, `"0x01"`)
	b, nb := seqServer(t, `"0x02"`, `"0x01"`)
	c := New([]string{a.URL, b.URL}, nil)
	got, _, err := c.Agreed(context.Background(), "eth_getCode", nil, 0)
	if err != nil || string(got) != `"0x01"` {
		t.Fatalf("got %s %v", got, err)
	}
	if *nb != 2 {
		t.Fatalf("재조회가 1번이어야 합니다: %d", *nb)
	}
}

func TestAgreedDisagreeTwice(t *testing.T) {
	a, _ := seqServer(t, `"0x01"`)
	b, nb := seqServer(t, `"0x02"`)
	c := New([]string{a.URL, b.URL}, nil)
	_, _, err := c.Agreed(context.Background(), "eth_getCode", nil, 0)
	if !errors.Is(err, ErrDisagree) {
		t.Fatalf("ErrDisagree가 아닙니다: %v", err)
	}
	if *nb != 2 {
		t.Fatalf("재조회는 1번만: %d", *nb)
	}
}

func TestCallAllReturnsEach(t *testing.T) {
	a, _ := seqServer(t, `"0x01"`)
	b, _ := seqServer(t, `"0x02"`)
	c := New([]string{a.URL, b.URL}, nil)
	got, err := c.CallAll(context.Background(), "eth_chainId", nil)
	if err != nil || len(got) != 2 || string(got[1]) != `"0x02"` {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestFailedClient(t *testing.T) {
	want := errors.New("환경 변수 X가 비어 있습니다")
	c := NewFailed(want)
	if _, err := c.Call(context.Background(), "m", nil); !errors.Is(err, want) {
		t.Fatalf("%v", err)
	}
}
