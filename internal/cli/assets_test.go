package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

type fakeCrtsh struct {
	mu      sync.Mutex
	queries []url.Values
	uas     []string
}

func (f *fakeCrtsh) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queries)
}

// useFakeCrtsh points adk assets at an httptest server instead of crt.sh.
func useFakeCrtsh(t *testing.T, status int, ctype, body string) *fakeCrtsh {
	t.Helper()
	f := &fakeCrtsh{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries = append(f.queries, r.URL.Query())
		f.uas = append(f.uas, r.UserAgent())
		f.mu.Unlock()
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	oldURL, oldBackoff := crtshBaseURL, crtshBackoff
	t.Cleanup(func() { crtshBaseURL, crtshBackoff = oldURL, oldBackoff })
	crtshBaseURL = srv.URL
	crtshBackoff = func(int) time.Duration { return 0 }
	return f
}

func sampleCrtsh(t *testing.T) *fakeCrtsh {
	b, err := os.ReadFile("../../testdata/assets/crtsh/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	return useFakeCrtsh(t, 200, "application/json", string(b))
}

func TestAssetsE2E(t *testing.T) {
	f := sampleCrtsh(t)
	t.Chdir(t.TempDir()) // no .adkignore here
	code, out, stderr := runCLI(t, "assets", "example.test", "--exclude-expired")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"# adk 자산 리포트", "- 대상: example.test",
		"인증서 투명성(CT) 공개 기록만 조회했고, 찾은 주소에는 접속하지 않았습니다.",
		"## 확인해 볼 서브도메인 (3개)", "`api.example.test`", "`www.example.test`", "`example.test`",
		"이 리포트는 법률 자문이 아닙니다.",
		"## 이 목록을 보는 법", "서버 48대 중 1대가 자산 목록에서 빠져 있었습니다", // explain/AS-002.md
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "지금 당장 고칠 것") {
		t.Errorf("assets report must not have the fix-now section:\n%s", out)
	}
	if f.requests() != 1 {
		t.Fatalf("requests %d", f.requests())
	}
	q := f.queries[0]
	if q.Get("dNSName") != "example.test" || q.Get("exclude") != "expired" || q.Get("output") != "json" {
		t.Errorf("query %v", q)
	}
	if want := "adk/" + toolVersion() + " (+https://github.com/iimmuunnee/ai-defense-kit)"; f.uas[0] != want {
		t.Errorf("UA %q want %q", f.uas[0], want)
	}

	// without --exclude-expired the parameter is not sent
	runCLI(t, "assets", "example.test")
	if q := f.queries[1]; q.Has("exclude") {
		t.Errorf("query %v", q)
	}
}

func TestAssetsDomainCleanup(t *testing.T) {
	f := useFakeCrtsh(t, 200, "application/json", "[]")
	t.Chdir(t.TempDir())
	for i, in := range []string{
		"https://Example.TEST/path?x=1#y",
		"  example.test  ",
		"HTTP://example.test:8443",
		"example.test.",
		"Example.COM.example.test?q", // only the suffix check matters to crt.sh
	} {
		code, out, stderr := runCLI(t, "assets", in)
		if code != 0 {
			t.Fatalf("%q: exit %d %s", in, code, stderr)
		}
		got := f.queries[i].Get("dNSName")
		want := "example.test"
		if i == 4 {
			want = "example.com.example.test"
		}
		if got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
		if !strings.Contains(out, "인증서 공개 기록에서 찾은 서브도메인이 없습니다.") {
			t.Errorf("%q: empty message missing:\n%s", in, out)
		}
	}
}

func TestAssetsDomainRejected(t *testing.T) {
	f := useFakeCrtsh(t, 200, "application/json", "[]")
	for in, want := range map[string]string{
		"":                       "도메인이 비어 있습니다",
		"   ":                    "도메인이 비어 있습니다",
		"https://":               "도메인이 비어 있습니다",
		"*.example.test":         "*",
		"exa%mple.test":          "%",
		"192.0.2.10":             "IP 주소",
		"https://192.0.2.10:443": "IP 주소",
		"2001:db8::1":            "IP 주소",
		"[2001:db8::1]:443":      "IP 주소",
		"localhost":              "점(.)",
		"bad_name.example.test":  "올바른 도메인 이름이 아닙니다",
		"x-.example.test":        "올바른 도메인 이름이 아닙니다",
		"a..example.test":        "올바른 도메인 이름이 아닙니다",
		"user@example.test":      "올바른 도메인 이름이 아닙니다",
		"한글.example.test":        "xn--",
		"예시.kr":                  "퓨니코드",
	} {
		code, _, stderr := runCLI(t, "assets", in)
		if code != 2 || !strings.Contains(stderr, want) {
			t.Errorf("%q: code=%d stderr=%q (want %q)", in, code, stderr, want)
		}
	}
	if f.requests() != 0 {
		t.Errorf("rejected domains must not be looked up: %d requests", f.requests())
	}
}

func TestAssetsArgs(t *testing.T) {
	f := useFakeCrtsh(t, 200, "application/json", "[]")
	for _, args := range [][]string{
		{"assets"},
		{"assets", "a.example.test", "b.example.test"},
		{"assets", "example.test", "--nope"},
		{"assets", "example.test", "--format", "xml"},
		{"assets", "example.test", "--format", "md,json"}, // two formats need --out
		{"assets", "example.test", "--fail-on", "high"},
	} {
		code, _, stderr := runCLI(t, args...)
		if code != 2 || stderr == "" {
			t.Errorf("%v: code=%d stderr=%q", args, code, stderr)
		}
	}
	if f.requests() != 0 {
		t.Errorf("requests %d", f.requests())
	}
	code, out, _ := runCLI(t, "assets", "--help")
	if code != 0 || !strings.Contains(out, "adk assets <도메인>") {
		t.Errorf("help: %d %s", code, out)
	}
}

func TestAssetsOffline(t *testing.T) {
	f := useFakeCrtsh(t, 200, "application/json", "[]")
	for _, args := range [][]string{
		{"assets", "example.test", "--offline"},
		{"assets", "--offline=false", "example.test"},
	} {
		code, _, stderr := runCLI(t, args...)
		if code != 2 || !strings.Contains(stderr, "adk assets는 인터넷 조회가 필요해 --offline을 쓸 수 없습니다.") {
			t.Errorf("%v: code=%d stderr=%q", args, code, stderr)
		}
	}
	if f.requests() != 0 {
		t.Errorf("requests %d", f.requests())
	}
}

func TestAssetsKnown(t *testing.T) {
	sampleCrtsh(t)
	dir := t.TempDir()
	t.Chdir(dir)
	known := filepath.Join(dir, "known.txt")
	if err := os.WriteFile(known, []byte("# 우리 이름\nexample.test\nwww.example.test # 홈페이지\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runCLI(t, "assets", "example.test", "--known", known)
	if code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	if !strings.Contains(out, "## 확인해 볼 서브도메인 (1개)") || !strings.Contains(out, "`api.example.test`") ||
		strings.Contains(out, "`www.example.test`") || !strings.Contains(out, "- 알려진 목록: "+known) ||
		!strings.Contains(out, "`--known`으로 넘긴") { // explain/AS-001.md
		t.Errorf("unexpected:\n%s", out)
	}

	// all known → not "nothing found"
	if err := os.WriteFile(known, []byte("*.example.test\nexample.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI(t, "assets", "example.test", "--known", known)
	if code != 0 || !strings.Contains(out, "알려진 목록에 없는 서브도메인이 없습니다.") {
		t.Errorf("all known: %d\n%s", code, out)
	}
}

func TestAssetsKnownErrors(t *testing.T) {
	f := useFakeCrtsh(t, 200, "application/json", "[]")
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("ok.example.test\nbad name.example.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "assets", "example.test", "--known", bad)
	if code != 2 || !strings.Contains(stderr, bad+":2: 올바른 도메인 이름이 아닙니다: \"bad name.example.test\"") {
		t.Errorf("bad known: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = runCLI(t, "assets", "example.test", "--known", filepath.Join(dir, "none.txt"))
	if code != 2 || !strings.Contains(stderr, "알려진 목록 파일을 읽지 못했습니다") {
		t.Errorf("missing known: code=%d stderr=%q", code, stderr)
	}
	if f.requests() != 0 {
		t.Errorf("a broken --known must stop before the lookup: %d", f.requests())
	}
}

func TestAssetsCrtshFails(t *testing.T) {
	f := useFakeCrtsh(t, 502, "text/html", "<html>502 Bad Gateway</html>")
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{"assets", "example.test"}, {"assets", "example.test", "--strict"}} {
		code, out, stderr := runCLI(t, args...)
		if code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
		if !strings.Contains(stderr, "실행된 점검이 하나도 없습니다.") || !strings.Contains(stderr, "assets: crt.sh 조회에 실패했습니다") {
			t.Errorf("%v: stderr %q", args, stderr)
		}
		if strings.Contains(out, "서브도메인이 없습니다") {
			t.Errorf("a failed lookup must not look empty:\n%s", out)
		}
	}
	if f.requests() != 6 { // 3 attempts each
		t.Errorf("requests %d", f.requests())
	}
}

func TestAssetsTruncatedWarns(t *testing.T) {
	useFakeCrtsh(t, 200, "application/json",
		`[{"name_value":"a.example.test","not_before":"2026-01-01T00:00:00","not_after":"2027-01-01T00:00:00","result_count":10000,"id":1}]`)
	t.Chdir(t.TempDir())
	code, out, stderr := runCLI(t, "assets", "example.test")
	const warn = "crt.sh 결과가 10000행 한도에 닿아 일부만 받았을 수 있습니다. --exclude-expired로 다시 확인해 보세요."
	if code != 0 || !strings.Contains(stderr, warn) || !strings.Contains(out, warn) {
		t.Errorf("code=%d stderr=%q\n%s", code, stderr, out)
	}
}

func TestAssetsFormatsAndIgnore(t *testing.T) {
	sampleCrtsh(t)
	dir := t.TempDir()
	t.Chdir(dir)
	fp := finding.MakeFingerprint("AS-002", "www.example.test", "www.example.test")
	if err := os.WriteFile(filepath.Join(dir, ".adkignore"), []byte(fp+" # 우리 홈페이지\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	code, stdout, stderr := runCLI(t, "assets", "example.test", "--format", "md,json", "--out", outDir)
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d stdout=%q stderr=%s", code, stdout, stderr)
	}
	md, err := os.ReadFile(filepath.Join(outDir, "adk-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(md), "`www.example.test`") || !strings.Contains(string(md), "무시함: 1개 (.adkignore)") ||
		!strings.Contains(string(md), "## 확인해 볼 서브도메인 (2개)") {
		t.Errorf("md:\n%s", md)
	}
	b, err := os.ReadFile(filepath.Join(outDir, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Kind     string `json:"kind"`
		Target   string `json:"target"`
		Ignored  int    `json:"ignored"`
		Findings []struct {
			ID, Location, Evidence, Fingerprint string
			Severity                            string
		} `json:"findings"`
		Assets []struct {
			Name        string `json:"name"`
			CertCount   int    `json:"cert_count"`
			Fingerprint string `json:"fingerprint"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "assets" || rep.Target != "example.test" || rep.Ignored != 1 || len(rep.Findings) != 2 || len(rep.Assets) != 2 {
		t.Fatalf("%+v", rep)
	}
	for i, f := range rep.Findings {
		if f.ID != "AS-002" || f.Severity != "info" || !strings.HasSuffix(f.Evidence, "(소유 미확인)") ||
			rep.Assets[i].Fingerprint != f.Fingerprint || rep.Assets[i].Name != f.Location {
			t.Errorf("%d: %+v / %+v", i, f, rep.Assets[i])
		}
	}
	if rep.Assets[1].Name != "example.test" || rep.Assets[1].CertCount != 2 {
		t.Errorf("%+v", rep.Assets)
	}
}

func TestAssetsAttachesMappings(t *testing.T) {
	sampleCrtsh(t)
	t.Chdir(t.TempDir())
	tmp := t.TempDir()
	code, _, se := runCLI(t, "assets", "example.test", "--format", "json", "--out", tmp)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		entries, _ := os.ReadDir(tmp)
		t.Fatalf("read: %v (%v)", err, entries)
	}
	var rep struct {
		Findings []struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			Mappings []struct {
				ID           string `json:"id"`
				ReviewStatus string `json:"review_status"`
			} `json:"mappings"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range rep.Findings {
		// mappings/kinds.yaml: AS-001, AS-002 -> ISMSP-1.2.1 (정보자산 식별)
		if len(f.Mappings) != 1 || f.Mappings[0].ID != "ISMSP-1.2.1" || f.Mappings[0].ReviewStatus != "checked" {
			t.Errorf("%s (%s): mappings = %+v, want [ISMSP-1.2.1 checked]", f.ID, f.Kind, f.Mappings)
		}
	}
}
