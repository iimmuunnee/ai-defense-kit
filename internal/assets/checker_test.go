package assets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/assets/ctlog"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

var explainFS = fstest.MapFS{
	"explain/AS-001.md": {Data: []byte("목록에 없는 이름 설명")},
	"explain/AS-002.md": {Data: []byte("찾은 이름 설명")},
}

// checkerNow는 sample.json 안의 날짜와 맞춘 기준 시각이다.
// 이 시각에 example.test의 두 번째 인증서(~2027-05-02)만 아직 유효하다.
var checkerNow = time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)

func crtsh(t *testing.T, status int, ctype, body string) (ctlog.Options, *[]string) {
	t.Helper()
	var uas []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uas = append(uas, r.UserAgent())
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return ctlog.Options{BaseURL: srv.URL, UserAgent: "adk/test", Attempts: 1, Backoff: func(int) time.Duration { return 0 }}, &uas
}

func sampleBody(t *testing.T) string {
	b, err := os.ReadFile("../../testdata/assets/crtsh/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func run(t *testing.T, c checker.Checker) (checker.Result, error) {
	return c.Run(context.Background(), checker.Target{Domain: "example.test"})
}

func TestCheckerWithoutKnown(t *testing.T) {
	opt, uas := crtsh(t, 200, "application/json", sampleBody(t))
	c := NewChecker(explainFS, opt, nil, func() time.Time { return checkerNow })
	if c.Name() != "assets" {
		t.Fatalf("name %q", c.Name())
	}
	res, err := run(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(*uas) != 1 || (*uas)[0] != "adk/test" {
		t.Errorf("UA %v", *uas)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings %v", res.Warnings)
	}
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Location)
		if f.ID != "AS-002" || f.Source != "assets" || f.Severity != finding.Info || f.Confidence != finding.Suspect {
			t.Errorf("%+v", f)
		}
		if f.Kind != "AS-002" {
			t.Errorf("Kind %q", f.Kind)
		}
		if f.Title != "인증서 공개 기록에서 찾은 서브도메인: "+f.Location || f.ExplainKo != "찾은 이름 설명" {
			t.Errorf("title/explain %q %q", f.Title, f.ExplainKo)
		}
		if f.Fingerprint != finding.MakeFingerprint("AS-002", f.Location, f.Location) {
			t.Errorf("fingerprint %s", f.Fingerprint)
		}
	}
	if strings.Join(got, ",") != "api.example.test,example.test,www.example.test" {
		t.Fatalf("locations %v", got)
	}
	ev := map[string]string{}
	for _, f := range res.Findings {
		ev[f.Location] = f.Evidence
	}
	// example.test: 2026-10-14~2027-01-11, 2026-02-01~2027-05-02 두 인증서
	if want := "인증서 2개, 처음 발급 2026-02-01, 마지막 만료 2027-05-02, 지금 유효함 (소유 미확인)"; ev["example.test"] != want {
		t.Errorf("evidence %q", ev["example.test"])
	}
	// api.example.test: 2027-02-18에 만료됨
	if want := "인증서 1개, 처음 발급 2026-11-20, 마지막 만료 2027-02-18, 지금 유효한 인증서 없음 (소유 미확인)"; ev["api.example.test"] != want {
		t.Errorf("evidence %q", ev["api.example.test"])
	}

	as := c.Assets()
	if len(as) != 3 || as[0].Name != "api.example.test" {
		t.Errorf("assets %+v", as)
	}
}

func TestCheckerWithKnown(t *testing.T) {
	opt, _ := crtsh(t, 200, "application/json", sampleBody(t))
	k, err := LoadKnown(write(t, "example.test\nwww.example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := NewChecker(explainFS, opt, &k, func() time.Time { return checkerNow })
	res, err := run(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("%+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != "AS-001" {
		t.Errorf("Kind %q", f.Kind)
	}
	if f.ID != "AS-001" || f.Location != "api.example.test" || f.Title != "목록에 없는 서브도메인: api.example.test" ||
		f.ExplainKo != "목록에 없는 이름 설명" || f.Fingerprint != finding.MakeFingerprint("AS-001", "api.example.test", "api.example.test") {
		t.Errorf("%+v", f)
	}
	if len(c.Assets()) != 1 {
		t.Errorf("Assets는 결과와 같은 이름만: %+v", c.Assets())
	}
}

func TestCheckerTruncatedWarning(t *testing.T) {
	body := `[{"name_value":"a.example.test","not_before":"2026-01-01T00:00:00","not_after":"2027-01-01T00:00:00","result_count":10000,"id":1}]`
	opt, _ := crtsh(t, 200, "application/json", body)
	res, err := run(t, NewChecker(explainFS, opt, nil, func() time.Time { return checkerNow }))
	if err != nil {
		t.Fatal(err)
	}
	want := "crt.sh 결과가 10000행 한도에 닿아 일부만 받았을 수 있습니다. --exclude-expired로 다시 확인해 보세요."
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("%v", res.Warnings)
	}
	if len(res.Findings) != 1 {
		t.Errorf("%+v", res.Findings)
	}
}

func TestCheckerTruncatedWarningExcludeExpired(t *testing.T) {
	body := `[{"name_value":"a.example.test","not_before":"2026-01-01T00:00:00","not_after":"2027-01-01T00:00:00","result_count":10000,"id":1}]`
	opt, _ := crtsh(t, 200, "application/json", body)
	opt.ExcludeExpired = true
	res, err := run(t, NewChecker(explainFS, opt, nil, func() time.Time { return checkerNow }))
	if err != nil {
		t.Fatal(err)
	}
	want := "crt.sh 결과가 10000행 한도에 닿아 일부만 받았을 수 있습니다. 하위 도메인별로 나눠 조회해 보세요."
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("%v", res.Warnings)
	}
}

func TestCheckerFetchFails(t *testing.T) {
	opt, _ := crtsh(t, 502, "text/html", "<html>502 Bad Gateway</html>")
	res, err := run(t, NewChecker(explainFS, opt, nil, nil))
	if err == nil || !strings.Contains(err.Error(), "crt.sh 조회에 실패했습니다") {
		t.Fatalf("err %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%+v", res.Findings)
	}
}

func TestCheckerEmpty(t *testing.T) {
	opt, _ := crtsh(t, 200, "application/json", "[]")
	res, err := run(t, NewChecker(nil, opt, nil, nil))
	if err != nil || len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestCheckerNeedsDomain(t *testing.T) {
	opt, uas := crtsh(t, 200, "application/json", "[]")
	_, err := NewChecker(nil, opt, nil, nil).Run(context.Background(), checker.Target{})
	if err == nil || len(*uas) != 0 {
		t.Fatalf("도메인 없이 조회하면 안 됨: %v %v", err, *uas)
	}
}

func TestAssetsRecordsExternalData(t *testing.T) {
	t0 := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	opt, _ := crtsh(t, 200, "application/json", sampleBody(t))
	res, err := run(t, NewChecker(explainFS, opt, nil, func() time.Time { return t0 }))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.External) != 1 {
		t.Fatalf("External = %+v", res.External)
	}
	g := res.External[0]
	if g.Name != "crt.sh" || g.Mode != checker.ModeOnline || g.Status != checker.ExternalUsed || g.FetchedAt == nil || !g.FetchedAt.Equal(t0) {
		t.Errorf("success: %+v", g)
	}

	opt, _ = crtsh(t, 502, "text/html", "<html>502</html>")
	res, err = run(t, NewChecker(explainFS, opt, nil, func() time.Time { return t0 }))
	if err == nil {
		t.Fatal("want error")
	}
	if len(res.External) != 1 {
		t.Fatalf("External = %+v", res.External)
	}
	g = res.External[0]
	if g.Name != "crt.sh" || g.Mode != checker.ModeOnline || g.Status != checker.ExternalFailed || g.FetchedAt != nil {
		t.Errorf("failure: %+v", g)
	}
}
