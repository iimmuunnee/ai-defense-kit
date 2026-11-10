package cli

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestVersionCommandPrintsVersionAndHashes(t *testing.T) {
	old := Version
	Version = "1.2.3"
	t.Cleanup(func() { Version = old })

	code, out, errOut := runCLI(t, "version")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	if !strings.HasPrefix(out, "adk 1.2.3\n") {
		t.Fatalf("첫 줄이 버전이어야 합니다: %q", out)
	}
	if !strings.Contains(out, "커밋: ") {
		t.Fatalf("커밋 줄이 없습니다: %q", out)
	}
	for _, label := range []string{"규칙 데이터", "설명 데이터", "고치는 방법 데이터", "매핑 데이터"} {
		if !regexp.MustCompile(label + `: [0-9a-f]{16}\n`).MatchString(out) {
			t.Fatalf("%s 해시 줄이 없습니다: %q", label, out)
		}
	}
}

func TestDashDashVersionSameAsVersion(t *testing.T) {
	_, a, _ := runCLI(t, "version")
	code, b, _ := runCLI(t, "--version")
	if code != 0 || a != b || a == "" {
		t.Fatalf("version=%q --version=%q code=%d", a, b, code)
	}
}

func TestVersionInfoFallsBackWhenNothingLinked(t *testing.T) {
	old := Version
	Version = ""
	t.Cleanup(func() { Version = old })
	v, _, hashes := VersionInfo()
	if v == "" {
		t.Fatal("버전이 비어 있습니다")
	}
	if len(hashes) != 4 {
		t.Fatalf("해시 묶음 4개를 기대했습니다: %v", hashes)
	}
}

func TestDataHashIgnoresLineEndingsButNotContentOrPath(t *testing.T) {
	lf := fstest.MapFS{"a/x.yaml": {Data: []byte("k: 1\nj: 2\n")}, "a/y.yaml": {Data: []byte("z\n")}}
	crlf := fstest.MapFS{"a/x.yaml": {Data: []byte("k: 1\r\nj: 2\r\n")}, "a/y.yaml": {Data: []byte("z\r\n")}}
	if hashDir(lf, "a") != hashDir(crlf, "a") {
		t.Fatal("줄바꿈 차이가 해시를 바꿉니다")
	}
	changed := fstest.MapFS{"a/x.yaml": {Data: []byte("k: 1\nj: 3\n")}, "a/y.yaml": {Data: []byte("z\n")}}
	if hashDir(lf, "a") == hashDir(changed, "a") {
		t.Fatal("내용이 바뀌어도 해시가 같습니다")
	}
	moved := fstest.MapFS{"a/x2.yaml": {Data: []byte("k: 1\nj: 2\n")}, "a/y.yaml": {Data: []byte("z\n")}}
	if hashDir(lf, "a") == hashDir(moved, "a") {
		t.Fatal("경로가 바뀌어도 해시가 같습니다")
	}
}

func TestReportCarriesToolVersion(t *testing.T) {
	useFakeDeps(t)
	old := Version
	Version = "" // 링크 값이 없을 때도 VersionInfo를 거쳐 값이 채워져야 한다
	t.Cleanup(func() { Version = old })
	want, _, _ := VersionInfo()
	if want == "" {
		t.Fatal("VersionInfo가 빈 버전을 돌려줍니다")
	}
	code, out, _ := runCLI(t, "scan", t.TempDir(), "--fail-on", "none")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "- 도구 버전: "+want+"\n") {
		t.Fatalf("리포트의 도구 버전이 %q가 아닙니다: %.400s", want, out)
	}
	Version = "9.9.9"
	_, out, _ = runCLI(t, "scan", t.TempDir(), "--fail-on", "none")
	if !strings.Contains(out, "- 도구 버전: 9.9.9\n") {
		t.Fatalf("링크 값이 리포트에 없습니다: %.400s", out)
	}
}
