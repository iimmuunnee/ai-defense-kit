package mapping

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func itemYAML(id, status string) string {
	s := "id: " + id + "\nname: 접근통제\nclause: 2.10.4\nsource_url: https://example.kr/isms\nsource_version: \"2023\"\nsummary_ko: 요약\nreview:\n  status: " + status + "\n"
	if status != StatusDraft {
		s += "  checked_by: Claude (AI)\n  checked_at: 2026-11-05\n  quote: 인용\n"
	}
	return s
}

func validFS() fstest.MapFS {
	return fstest.MapFS{
		"mappings/isms-p/ISMSP-2.10.4.yaml": {Data: []byte(itemYAML("ISMSP-2.10.4", "checked"))},
		"mappings/kinds.yaml":               {Data: []byte("vuln-lib: [ISMSP-2.10.4]\n")},
	}
}

func TestLoadValid(t *testing.T) {
	c, err := Load(validFS())
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("Len=%d", c.Len())
	}
	it, ok := c.Item("ISMSP-2.10.4")
	if !ok {
		t.Fatal("missing")
	}
	want := Item{ID: "ISMSP-2.10.4", Name: "접근통제", Clause: "2.10.4", SourceURL: "https://example.kr/isms", SourceVersion: "2023", SummaryKo: "요약",
		Review: Review{Status: "checked", CheckedBy: "Claude (AI)", CheckedAt: "2026-11-05", Quote: "인용"}}
	if it != want {
		t.Fatalf("got %+v", it)
	}
}

func TestLoadNoDir(t *testing.T) {
	c, err := Load(fstest.MapFS{})
	if err != nil || c.Len() != 0 {
		t.Fatalf("len=%d err=%v", c.Len(), err)
	}
	fsys := validFS()
	delete(fsys, "mappings/kinds.yaml")
	if _, err := Load(fsys); err != nil {
		t.Fatal(err)
	}
}

func TestLoadErrors(t *testing.T) {
	const p = "mappings/isms-p/ISMSP-2.10.4.yaml"
	good := itemYAML("ISMSP-2.10.4", "checked")
	mod := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	cases := []struct {
		name string
		fs   fstest.MapFS
		path string
	}{
		{"중복 ID", fstest.MapFS{p: {Data: []byte(good)}, "mappings/other/ISMSP-2.10.4.yaml": {Data: []byte(good)}}, "mappings/other/ISMSP-2.10.4.yaml"},
		{"파일 이름 불일치", fstest.MapFS{"mappings/a/ISMSP-1.yaml": {Data: []byte(good)}}, "mappings/a/ISMSP-1.yaml"},
		{"모르는 키", fstest.MapFS{p: {Data: []byte(good + "foo: 1\n")}}, p},
		{"잘못된 status", fstest.MapFS{p: {Data: []byte(mod("status: checked", "status: done"))}}, p},
		{"checked_by 빔", fstest.MapFS{p: {Data: []byte(mod("  checked_by: Claude (AI)\n", ""))}}, p},
		{"checked_at 빔", fstest.MapFS{p: {Data: []byte(mod("  checked_at: 2026-11-05\n", ""))}}, p},
		{"날짜 형식", fstest.MapFS{p: {Data: []byte(mod("2026-11-05", "2026/11/05"))}}, p},
		{"source_url 빔", fstest.MapFS{p: {Data: []byte(mod("source_url: https://example.kr/isms\n", ""))}}, p},
		{"source_url http", fstest.MapFS{p: {Data: []byte(mod("https://example", "http://example"))}}, p},
		{"name 빔", fstest.MapFS{p: {Data: []byte(mod("name: 접근통제\n", ""))}}, p},
		{"source_version 빔", fstest.MapFS{p: {Data: []byte(mod("source_version: \"2023\"\n", ""))}}, p},
		{"kinds 모르는 키", fstest.MapFS{p: {Data: []byte(good)}, "mappings/kinds.yaml": {Data: []byte("foo: [ISMSP-2.10.4]\n")}}, "mappings/kinds.yaml"},
		{"kinds 없는 ID", fstest.MapFS{p: {Data: []byte(good)}, "mappings/kinds.yaml": {Data: []byte("vuln-lib: [NOPE]\n")}}, "mappings/kinds.yaml"},
		{"kinds 빈 문자열", fstest.MapFS{p: {Data: []byte(good)}, "mappings/kinds.yaml": {Data: []byte("vuln-lib: [\"\"]\n")}}, "mappings/kinds.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.fs)
			if err == nil {
				t.Fatal("오류가 있어야 함")
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("경로 %s 없음: %v", tc.path, err)
			}
		})
	}
}

func TestAttach(t *testing.T) {
	c, _ := Load(validFS())
	fs := []finding.Finding{
		{ID: "A", Kind: "KR-PAY-002", Mappings: []finding.Mapping{{ID: "ISMSP-2.10.4"}}},
		{ID: "B", Kind: "vuln-lib"},
	}
	w := c.Attach(fs)
	if len(w) != 0 {
		t.Fatalf("warnings %v", w)
	}
	want := finding.Mapping{ID: "ISMSP-2.10.4", Name: "접근통제", Clause: "2.10.4", ReviewStatus: "checked", CheckedBy: "Claude (AI)", CheckedAt: "2026-11-05", SourceURL: "https://example.kr/isms"}
	for _, f := range fs {
		if len(f.Mappings) != 1 || f.Mappings[0] != want {
			t.Fatalf("%s: %+v", f.ID, f.Mappings)
		}
	}
}

func TestAttachDedup(t *testing.T) {
	fsys := validFS()
	fsys["mappings/isms-p/ISMSP-1.1.1.yaml"] = &fstest.MapFile{Data: []byte(itemYAML("ISMSP-1.1.1", "checked"))}
	fsys["mappings/kinds.yaml"] = &fstest.MapFile{Data: []byte("vuln-lib: [ISMSP-2.10.4, ISMSP-1.1.1]\n")}
	c, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	fs := []finding.Finding{{ID: "A", Kind: "vuln-lib", Mappings: []finding.Mapping{{ID: "ISMSP-2.10.4"}}}}
	c.Attach(fs)
	m := fs[0].Mappings
	if len(m) != 2 || m[0].ID != "ISMSP-1.1.1" || m[1].ID != "ISMSP-2.10.4" {
		t.Fatalf("%+v", m)
	}
}

func TestAttachUnknownID(t *testing.T) {
	c, _ := Load(validFS())
	fs := []finding.Finding{
		{ID: "KR-X-1", Mappings: []finding.Mapping{{ID: "ISMSP-9.9.9"}}},
		{ID: "KR-X-2", Mappings: []finding.Mapping{{ID: "ISMSP-9.9.9"}}},
	}
	w := c.Attach(fs)
	if len(w) != 1 || !strings.Contains(w[0], "ISMSP-9.9.9") {
		t.Fatalf("warnings %v", w)
	}
	for _, f := range fs {
		if len(f.Mappings) != 1 || f.Mappings[0] != (finding.Mapping{ID: "ISMSP-9.9.9", ReviewStatus: "draft"}) {
			t.Fatalf("%+v", f.Mappings)
		}
	}
}

func TestAttachDraftItem(t *testing.T) {
	fsys := fstest.MapFS{"mappings/x/ISMSP-1.1.1.yaml": {Data: []byte(itemYAML("ISMSP-1.1.1", "draft"))}}
	c, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	fs := []finding.Finding{{ID: "A", Mappings: []finding.Mapping{{ID: "ISMSP-1.1.1"}}}}
	c.Attach(fs)
	m := fs[0].Mappings[0]
	if m.ReviewStatus != "draft" || m.CheckedBy != "" || m.CheckedAt != "" {
		t.Fatalf("%+v", m)
	}
}

func TestCatalogItemsSorted(t *testing.T) {
	fsys := validFS()
	fsys["mappings/isms-p/ISMSP-1.1.1.yaml"] = &fstest.MapFile{Data: []byte(itemYAML("ISMSP-1.1.1", "checked"))}
	c, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	items := c.Items()
	if len(items) != 2 || items[0].ID != "ISMSP-1.1.1" || items[1].ID != "ISMSP-2.10.4" {
		t.Fatalf("items=%v", items)
	}
	items[0].ID = "changed"
	if again := c.Items(); again[0].ID != "ISMSP-1.1.1" {
		t.Fatal("catalog was modified through the copy")
	}
	if _, ok := c.Item("ISMSP-1.1.1"); !ok {
		t.Fatal("catalog lost item")
	}
}
