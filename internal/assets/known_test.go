package assets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "known.txt")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKnown(t *testing.T) {
	k, err := LoadKnown(write(t, "\ufeff# 주석\r\nWWW.Example.Test\r\n\r\n  api.example.test.  \r\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"www.example.test", "API.example.test", "api.example.test."} {
		if !k.Has(n) {
			t.Errorf("%s 를 알아야 함", n)
		}
	}
	if k.Has("x.example.test") {
		t.Error("목록에 없는 이름")
	}
	k, err = LoadKnown(write(t, ""))
	if err != nil || k.Has("a.example.test") {
		t.Fatalf("빈 파일: %v", err)
	}
	if _, err := LoadKnown(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("없는 파일은 오류")
	}
}

func TestLoadKnownBadLine(t *testing.T) {
	_, err := LoadKnown(write(t, "ok.example.test\n# c\n\nbad name.example.test\n"))
	if err == nil || !strings.Contains(err.Error(), ":4:") {
		t.Fatalf("줄 번호가 든 오류여야 함: %v", err)
	}
	for _, bad := range []string{"_dmarc.example.test", "a@b.test", "*.", "*.*.example.test", "a..test"} {
		if _, err := LoadKnown(write(t, bad+"\n")); err == nil {
			t.Errorf("%q 는 오류여야 함", bad)
		}
	}
}

func TestKnownWildcard(t *testing.T) {
	k, err := LoadKnown(write(t, "*.Sub.Example.Test\n"))
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]bool{
		"a.sub.example.test":      true,
		"x.y.sub.example.test":    true,
		"sub.example.test":        false,
		"a.example.test":          false,
		"asub.example.test":       false,
		"a.sub.example.test.evil": false,
	} {
		if k.Has(n) != want {
			t.Errorf("Has(%q)=%v", n, !want)
		}
	}
}

func TestUnknown(t *testing.T) {
	k, _ := LoadKnown(write(t, "www.example.test\n*.dev.example.test\n"))
	in := []Asset{{Name: "api.example.test"}, {Name: "www.example.test"}, {Name: "a.dev.example.test"}, {Name: "dev.example.test"}}
	got := names(Unknown(in, k))
	if strings.Join(got, ",") != "api.example.test,dev.example.test" {
		t.Fatalf("%v", got)
	}
	if len(Unknown(nil, k)) != 0 {
		t.Error("빈 입력")
	}
}

func TestLoadKnownInlineComment(t *testing.T) {
	k, err := LoadKnown(write(t, "www.example.test # 홈페이지\r\napi.example.test\t# 결제 API\n*.dev.example.test   #개발\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"www.example.test", "api.example.test", "a.dev.example.test"} {
		if !k.Has(n) {
			t.Errorf("%s 를 알아야 함", n)
		}
	}
	// 공백 없이 붙은 '#'은 주석이 아니라 잘못된 이름이다.
	if _, err := LoadKnown(write(t, "www.example.test#홈\n")); err == nil {
		t.Error("공백 없는 '#'은 오류여야 함")
	}
}

func TestUnknownWildcardOnly(t *testing.T) {
	k, _ := LoadKnown(write(t, "*.dev.example.test\n"))
	in := []Asset{
		{Name: "dev.example.test", Wildcard: true},  // *.dev.example.test 인증서로만 봄 → 아는 것
		{Name: "dev2.example.test", Wildcard: true}, // 다른 이름
		{Name: "x.dev.example.test"},                // 그 아래 이름
	}
	got := names(Unknown(in, k))
	if strings.Join(got, ",") != "dev2.example.test" {
		t.Fatalf("%v", got)
	}
	// 평범한 인증서로도 본 dev.example.test는 *.dev 항목만으로는 아는 것이 아니다.
	if got := names(Unknown([]Asset{{Name: "dev.example.test"}}, k)); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}
