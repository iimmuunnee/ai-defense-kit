package assets

import (
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/assets/ctlog"
)

var now = time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)

func names(as []Asset) []string {
	var s []string
	for _, a := range as {
		s = append(s, a.Name)
	}
	return s
}

func TestCollectNormalizes(t *testing.T) {
	nv := strings.Join([]string{
		"  WWW.Example.Test ",
		"api.example.test.",
		"*.wild.example.test",
		"admin@example.test",
		"192.0.2.10",
		"example.test.evil.com",
		"evilexample.test",
		"example.test",
		"_dmarc.example.test",
		"bad_name.example.test",
		"-x.example.test",
		"",
		"xn--bcher-kva.example.test",
	}, "\n")
	got := Collect("Example.Test.", []ctlog.Entry{{NameValue: nv, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}, now)
	want := []string{"api.example.test", "example.test", "wild.example.test", "www.example.test", "xn--bcher-kva.example.test"}
	g := names(got)
	if strings.Join(g, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", g, want)
	}
	for _, a := range got {
		if a.Wildcard != (a.Name == "wild.example.test") {
			t.Errorf("%s Wildcard=%v", a.Name, a.Wildcard)
		}
	}
}

func TestCollectLongNames(t *testing.T) {
	long := strings.Repeat("a", 64) + ".example.test"
	ok := strings.Repeat("a", 63) + ".example.test"
	got := Collect("example.test", []ctlog.Entry{{NameValue: long + "\n" + ok}}, now)
	if len(got) != 1 || got[0].Name != ok {
		t.Fatalf("got %v", names(got))
	}
}

func TestCollectAggregates(t *testing.T) {
	d := func(day int) time.Time { return time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC) }
	entries := []ctlog.Entry{
		{NameValue: "a.example.test", NotBefore: d(10), NotAfter: d(20)},
		{NameValue: "a.example.test\na.example.test", NotBefore: d(5), NotAfter: now.Add(24 * time.Hour), ID: 2},
		{NameValue: "*.a.example.test", NotBefore: d(7), NotAfter: d(8)},
		{NameValue: "*.b.example.test", NotBefore: d(7), NotAfter: d(8)},
		{NameValue: "*.b.example.test\nb.example.test", NotBefore: d(7), NotAfter: d(8)},
		{NameValue: "c.example.test"},                                 // 0값 날짜
		{NameValue: "d.example.test", NotBefore: now.Add(-time.Hour)}, // NotAfter 0값
		{NameValue: "e.example.test", NotAfter: now.Add(time.Hour)},   // NotBefore 0값
	}
	m := map[string]Asset{}
	for _, a := range Collect("example.test", entries, now) {
		m[a.Name] = a
	}
	a := m["a.example.test"]
	if a.CertCount != 3 || !a.FirstSeen.Equal(d(5)) || !a.LastExpiry.Equal(now.Add(24*time.Hour)) || !a.StillValid || a.Wildcard {
		t.Errorf("a: %+v", a)
	}
	if m["b.example.test"].Wildcard != false || m["b.example.test"].StillValid {
		t.Errorf("b: %+v", m["b.example.test"])
	}
	for _, n := range []string{"c", "d", "e"} {
		if m[n+".example.test"].StillValid {
			t.Errorf("%s는 유효로 보면 안 됨", n)
		}
	}
	if len(Collect("example.test", nil, now)) != 0 {
		t.Error("빈 입력은 빈 결과")
	}
}

func TestCollectWildcardOnly(t *testing.T) {
	got := Collect("example.test", []ctlog.Entry{{NameValue: "*.a.example.test"}, {NameValue: "*.a.example.test"}}, now)
	if len(got) != 1 || !got[0].Wildcard || got[0].CertCount != 2 {
		t.Fatalf("%+v", got)
	}
}
