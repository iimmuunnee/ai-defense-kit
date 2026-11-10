package rules

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
)

const okRule = `id: T-1
title: 테스트
severity: high
match:
  files: ["**/*.py"]
  has_any: ["x"]
`

func TestLoadRejectsMissingFields(t *testing.T) {
	fsys := fstest.MapFS{"rules/kr/bad.yaml": {Data: []byte("title: t\nseverity: high\nmatch:\n  files: [\"*\"]\n  has_any: [\"x\"]\n")}}
	_, err := Load(fsys)
	if err == nil || !strings.Contains(err.Error(), "bad.yaml") || !strings.Contains(err.Error(), "id") {
		t.Fatalf("want error naming bad.yaml and id, got %v", err)
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/a.yaml":   {Data: []byte(okRule)},
		"rules/b/b.yaml": {Data: []byte(okRule)},
	}
	if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "T-1") {
		t.Fatalf("want duplicate error, got %v", err)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"scope":      strings.Replace(okRule, "match:\n", "match:\n  scope: global\n", 1),
		"confidence": okRule + "confidence: great\n",
		"glob":       strings.Replace(okRule, `"**/*.py"`, `"[a-"`, 1),
		"severity":   strings.Replace(okRule, "high", "huge", 1),
		"explain":    okRule + "explain: explain/none.md\n",
		"fix":        okRule + "fix: fixes/none/\n",
	}
	for key, body := range cases {
		_, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(body)}})
		if err == nil || !strings.Contains(err.Error(), "r.yaml") {
			t.Errorf("%s: want error naming r.yaml, got %v", key, err)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	rs, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(okRule)}})
	if err != nil || len(rs) != 1 {
		t.Fatalf("err=%v rs=%v", err, rs)
	}
	if rs[0].Match.Scope != "file" {
		t.Errorf("scope default = %q", rs[0].Match.Scope)
	}
}

func TestLoadEmbeddedRules(t *testing.T) {
	rs, err := Load(aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == "KR-PAY-002" {
			return
		}
	}
	t.Fatal("KR-PAY-002 not found")
}

func TestLoadRejectsBadRegex(t *testing.T) {
	for _, key := range []string{"has_any_regex", "missing_all_regex"} {
		body := strings.Replace(okRule, "  has_any: [\"x\"]\n", "  has_any: [\"x\"]\n  "+key+": [\"[a-\"]\n", 1)
		_, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(body)}})
		if err == nil || !strings.Contains(err.Error(), "r.yaml") || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: want error naming r.yaml and key, got %v", key, err)
		}
	}
}

func TestLoadRequiresHasAnyOrRegex(t *testing.T) {
	none := strings.Replace(okRule, "  has_any: [\"x\"]\n", "", 1)
	_, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(none)}})
	if err == nil || !strings.Contains(err.Error(), "r.yaml") || !strings.Contains(err.Error(), "has_any") {
		t.Fatalf("want error, got %v", err)
	}
	onlyRegex := strings.Replace(okRule, "  has_any: [\"x\"]\n", "  has_any_regex: [\"x+\"]\n", 1)
	if _, err := Load(fstest.MapFS{"rules/r.yaml": {Data: []byte(onlyRegex)}}); err != nil {
		t.Fatalf("has_any_regex alone should load: %v", err)
	}
}

// M3/M5: references carry checked_at only for sources that were opened, and
// Supabase references point at the exact docs files on the master branch.
func TestEmbeddedReferenceFacts(t *testing.T) {
	rs, err := Load(aidefensekit.Data)
	if err != nil {
		t.Fatal(err)
	}
	const sbDocs = "https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/"
	for _, r := range rs {
		for _, ref := range r.References {
			if strings.Contains(ref.URL, "rfc-editor.org") && ref.CheckedAt != "" {
				t.Errorf("%s: %s was never opened but has checked_at", r.ID, ref.URL)
			}
			if strings.Contains(ref.URL, "github.com/supabase/supabase") && !strings.HasPrefix(ref.URL, sbDocs) {
				t.Errorf("%s: %s is not an exact docs file URL", r.ID, ref.URL)
			}
		}
	}
}

// M4: explain texts hedge claims that could not be verified directly.
func TestExplainHedges(t *testing.T) {
	want := map[string][]string{
		"explain/KR-AUTH-001.md": {"직접 열어 확인하지 못했습니다", "`state = init`"},
		"explain/KR-AUTH-002.md": {"직접 열어 확인하지 못했습니다", "`state = init`"},
		"explain/SB-002.md":      {"Supabase 문서에 따르면", "번들에 포함됩니다"},
	}
	for name, subs := range want {
		b, err := fs.ReadFile(aidefensekit.Data, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range subs {
			if !strings.Contains(string(b), s) {
				t.Errorf("%s: missing %q", name, s)
			}
		}
	}
	if b, _ := fs.ReadFile(aidefensekit.Data, "explain/SB-002.md"); strings.Contains(string(b), "Next.js에서 `NEXT_PUBLIC_`으로 시작하는 환경 변수는") {
		t.Error("explain/SB-002.md still states the Next.js behavior as fact")
	}
}
