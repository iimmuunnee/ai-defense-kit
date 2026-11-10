package report

import (
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"testing/fstest"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
)

func TestHashTreeSameContentSameHash(t *testing.T) {
	a := fstest.MapFS{"d/x.yaml": {Data: []byte("one")}, "d/y.yaml": {Data: []byte("two")}}
	b := fstest.MapFS{"d/y.yaml": {Data: []byte("two")}, "d/x.yaml": {Data: []byte("one")}}
	ha, err := HashTree(a, "d")
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := HashTree(b, "d")
	if ha != hb {
		t.Fatalf("%s != %s", ha, hb)
	}
}

func TestHashTreeChangesWithContent(t *testing.T) {
	a := fstest.MapFS{"d/x": {Data: []byte("one")}}
	b := fstest.MapFS{"d/x": {Data: []byte("uno")}}
	ha, _ := HashTree(a, "d")
	hb, _ := HashTree(b, "d")
	if ha == hb {
		t.Fatal("same hash")
	}
}

func TestHashTreeChangesWithPath(t *testing.T) {
	a := fstest.MapFS{"d/x": {Data: []byte("one")}}
	b := fstest.MapFS{"d/z": {Data: []byte("one")}}
	ha, _ := HashTree(a, "d")
	hb, _ := HashTree(b, "d")
	if ha == hb {
		t.Fatal("same hash")
	}
}

func TestHashTreeNoAmbiguity(t *testing.T) {
	a := fstest.MapFS{"d/a": {Data: []byte("bc")}}
	b := fstest.MapFS{"d/ab": {Data: []byte("c")}}
	ha, _ := HashTree(a, "d")
	hb, _ := HashTree(b, "d")
	if ha == hb {
		t.Fatal("same hash")
	}
}

func TestHashTreeMissingDir(t *testing.T) {
	h, err := HashTree(fstest.MapFS{}, "nope")
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := HashTree(fstest.MapFS{"other/x": {Data: []byte("1")}}, "nope")
	if h != empty || len(h) != 64 {
		t.Fatalf("h=%q", h)
	}
	// SHA-256 of empty input.
	if h != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("not empty-input hash: %s", h)
	}
}

func TestHashTreeBuiltinIsStable(t *testing.T) {
	h1, err := HashTree(aidefensekit.Data, "rules")
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := HashTree(aidefensekit.Data, "rules")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(h1) || h1 != h2 {
		t.Fatalf("h1=%q h2=%q", h1, h2)
	}
}

func TestComponents(t *testing.T) {
	info := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "github.com/google/osv-scanner/v2", Version: "v2.7.0"},
		{Path: "github.com/zricethezav/gitleaks/v8", Version: "v8.30.1"},
		{Path: "gopkg.in/yaml.v3", Version: "v3.0.1"},
	}}
	got := Components(info)
	want := []Component{{"osv-scanner", "v2.7.0"}, {"gitleaks", "v8.30.1"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
	}
	nilGot := Components(nil)
	if nilGot == nil || len(nilGot) != 0 {
		t.Fatalf("nil case: %#v", nilGot)
	}
}

func TestTargetName(t *testing.T) {
	const none = "(이름 없음)"
	cases := map[string]string{
		"/a/my-app":  "my-app",
		"/a/my-app/": "my-app",
		"":           none,
		".":          none,
		"/":          none,
	}
	for in, want := range cases {
		if got := TargetName(in); got != want {
			t.Errorf("TargetName(%q)=%q want %q", in, got, want)
		}
	}
	if runtime.GOOS == "windows" {
		if got := TargetName(`C:\`); got != "C:" {
			t.Errorf(`TargetName(C:\)=%q`, got)
		}
		if got := TargetName(`C:\dev\my-app`); got != "my-app" {
			t.Errorf("got %q", got)
		}
	}
	_ = filepath.Separator
}

func TestScrub(t *testing.T) {
	s := `open C:\work\app\src\a.go and C:/work/app/b.go, plus D:\other\x and /tmp/priv/z`
	got := Scrub(s, `C:\work\app`, []string{`D:\other`, "/tmp/priv", ""})
	want := `open .\src\a.go and ./b.go, plus <경로>\x and <경로>/z`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	// Empty scanRoot and empty others do not break the text.
	if got := Scrub("abc", "", []string{""}); got != "abc" {
		t.Fatalf("got %q", got)
	}
	// Longer path first: scanRoot nested in an other path.
	got = Scrub("/r/sub/f", "/r", []string{"/r/sub"})
	if got != "<경로>/f" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(Scrub(`C:\work\app`, `C:\work\app`, nil), "work") {
		t.Fatal("leak")
	}
}
