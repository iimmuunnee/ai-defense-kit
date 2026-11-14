package checker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// 점검기마다 걸린 시간을 밀리초로 남긴다. 끝난 방식(완료, 실패, 시간 초과)과 상관없다.
func TestRunAllRecordsDuration(t *testing.T) {
	slow := fake{"slow", func(context.Context, Target) (Result, error) {
		time.Sleep(30 * time.Millisecond)
		return Result{}, nil
	}}
	fail := fake{"fail", func(context.Context, Target) (Result, error) {
		time.Sleep(30 * time.Millisecond)
		return Result{}, errors.New("boom")
	}}
	wait := fake{"wait", func(ctx context.Context, _ Target) (Result, error) {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}}
	_, st := RunAll(context.Background(), []Checker{slow, fail, wait}, Target{}, 80*time.Millisecond)
	for i, min := range []int64{30, 30, 80} {
		if st[i].DurationMS == nil {
			t.Fatalf("%s: no duration", st[i].Name)
		}
		if got := *st[i].DurationMS; got < min || got > 2000 {
			t.Errorf("%s: duration_ms = %d, want >= %d", st[i].Name, got, min)
		}
	}
}

// JSON에는 duration_ms로 나온다. RunAll을 거치지 않은 점검(watch, device)에는 없다.
func TestDurationJSON(t *testing.T) {
	ms := int64(1234)
	b, err := json.Marshal(CheckStatus{Name: "secrets", Status: StatusOK, DurationMS: &ms})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"duration_ms":1234`) {
		t.Errorf("JSON = %s", b)
	}
	b, _ = json.Marshal(CheckStatus{Name: "watch", Status: StatusOK})
	if strings.Contains(string(b), "duration") {
		t.Errorf("JSON without a measured duration = %s", b)
	}
}
