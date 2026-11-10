package rpc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgreeReturnsWhenAllAgree(t *testing.T) {
	calls := 0
	got, _, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		calls++
		return []string{"a", "a", "a"}, nil
	}, func(a, b string) bool { return a == b })
	if err != nil || got != "a" || calls != 1 {
		t.Fatalf("got=%q err=%v calls=%d", got, err, calls)
	}
}

func TestAgreeRetriesOnceThenDisagrees(t *testing.T) {
	calls := 0
	_, _, err := Agree(context.Background(), time.Millisecond, "x", func(context.Context) ([]string, []error) {
		calls++
		return []string{"a", "b"}, nil
	}, func(a, b string) bool { return a == b })
	if !errors.Is(err, ErrDisagree) || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestAgreeRecoversOnRetry(t *testing.T) {
	calls := 0
	got, _, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		calls++
		if calls == 1 {
			return []string{"a", "b"}, nil
		}
		return []string{"b", "b"}, nil
	}, func(a, b string) bool { return a == b })
	if err != nil || got != "b" || calls != 2 {
		t.Fatalf("got=%q err=%v calls=%d", got, err, calls)
	}
}

func TestAgreePassesAskErrorThrough(t *testing.T) {
	boom := errors.New("boom")
	_, _, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) { return nil, []error{boom} }, func(a, b string) bool { return a == b })
	if !errors.Is(err, boom) {
		t.Fatalf("err=%v", err)
	}
	_, _, err = Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) { return nil, nil }, func(a, b string) bool { return a == b })
	if err == nil {
		t.Fatal("빈 결과는 오류여야 합니다")
	}
}

func TestPostJSONSendsBodyAndScrubsErrors(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 200)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		_, _ = w.Write([]byte(`{"result":{}}`))
	}))
	defer srv.Close()
	c := New([]string{srv.URL + "/" + secretKey}, nil)
	if c.Len() != 1 {
		t.Fatalf("Len=%d", c.Len())
	}
	data, err := c.PostJSON(context.Background(), 0, map[string]any{"method": "ledger"})
	if err != nil || !strings.Contains(string(data), "result") || !strings.Contains(gotBody, `"method":"ledger"`) {
		t.Fatalf("data=%s err=%v body=%s", data, err, gotBody)
	}
	if _, err := c.PostJSON(context.Background(), 5, map[string]any{}); err == nil {
		t.Fatal("범위 밖 위치는 오류여야 합니다")
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	u := dead.URL + "/" + secretKey
	dead.Close()
	_, err = New([]string{u}, nil).PostJSON(context.Background(), 0, map[string]any{})
	if err == nil || strings.Contains(err.Error(), secretKey) || !strings.Contains(err.Error(), "RPC 1") {
		t.Fatalf("err=%v", err)
	}
	if _, err := NewFailed(errors.New("x")).PostJSON(context.Background(), 0, nil); err == nil {
		t.Fatal("failed client")
	}
}

func eqStr(a, b string) bool { return a == b }

func TestAgreePartialReturnsAnsweredValue(t *testing.T) {
	boom := errors.New("RPC 2: 연결하지 못했습니다")
	got, part, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		return []string{"a", ""}, []error{nil, boom}
	}, eqStr)
	if err != nil || got != "a" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if len(part.Missing) != 1 || part.Missing[0] != 2 {
		t.Fatalf("Missing=%v, want [2]", part.Missing)
	}
}

func TestAgreeFirstDownSecondAnswers(t *testing.T) {
	got, part, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		return []string{"", "b", "b"}, []error{errors.New("x"), nil, nil}
	}, eqStr)
	if err != nil || got != "b" || len(part.Missing) != 1 || part.Missing[0] != 1 {
		t.Fatalf("got=%q part=%v err=%v", got, part, err)
	}
}

func TestAgreeAllAnsweredHasNoMissing(t *testing.T) {
	_, part, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		return []string{"a", "a"}, []error{nil, nil}
	}, eqStr)
	if err != nil || len(part.Missing) != 0 {
		t.Fatalf("part=%v err=%v", part, err)
	}
}

func TestAgreeAllFailIsError(t *testing.T) {
	first := errors.New("RPC 1: 연결하지 못했습니다")
	_, _, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		return make([]string, 2), []error{first, errors.New("RPC 2: 연결하지 못했습니다")}
	}, eqStr)
	if !errors.Is(err, first) {
		t.Fatalf("err=%v", err)
	}
}

func TestAgreeAnsweredDisagreeIsError(t *testing.T) {
	calls := 0
	_, _, err := Agree(context.Background(), 0, "x", func(context.Context) ([]string, []error) {
		calls++
		return []string{"a", "b", ""}, []error{nil, nil, errors.New("down")}
	}, eqStr)
	if !errors.Is(err, ErrDisagree) || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}
