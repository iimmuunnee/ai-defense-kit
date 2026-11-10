package supabase

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

var testData = fstest.MapFS{
	"explain/SB-001.md":   {Data: []byte("설명")},
	"fixes/SB-001/sql.md": {Data: []byte("수정")},
}

func run(t *testing.T, root string) checker.Result {
	t.Helper()
	res, err := New(testData).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestName(t *testing.T) {
	if New(testData).Name() != "supabase" {
		t.Fatal("name")
	}
}

func TestNoMigrationsFolder(t *testing.T) {
	res := run(t, t.TempDir())
	if len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestVulnerable(t *testing.T) {
	res := run(t, "../../../testdata/supabase/vulnerable")
	if len(res.Findings) != 1 {
		t.Fatalf("%+v", res)
	}
	f := res.Findings[0]
	loc := "supabase/migrations/20260101000000_init.sql"
	if f.Kind != "SB-001" {
		t.Errorf("Kind = %q", f.Kind)
	}
	if f.ID != "SB-001" || f.Source != "supabase" || f.Severity != finding.High || f.Confidence != finding.Suspect ||
		f.Location != loc || f.Line != 2 || f.Evidence != "public.profiles" ||
		f.Title != "RLS가 켜지지 않은 테이블: public.profiles" ||
		f.ExplainKo != "설명" || f.Fix != "수정" ||
		len(f.References) != 1 || f.References[0] != "https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/database/postgres/row-level-security.mdx" || len(f.Mappings) != 0 ||
		f.Fingerprint != finding.MakeFingerprint("SB-001", loc, "public.profiles") {
		t.Fatalf("%+v", f)
	}
}

func TestSafe(t *testing.T) {
	if res := run(t, "../../../testdata/supabase/safe"); len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestMixed(t *testing.T) {
	res := run(t, "../../../testdata/supabase/mixed")
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Evidence+"@"+f.Location)
	}
	want := "public.notes@supabase/migrations/20260101000000_init.sql,public.Items@supabase/migrations/20260102000000_more.sql"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
}

func TestEventTriggerWarning(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "supabase", "migrations")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sql := "create table public.a (id int);\ncreate event trigger t on ddl_command_end execute function f(); -- alter table x enable row level security\nalter table y enable row level security;"
	os.WriteFile(filepath.Join(dir, "1.sql"), []byte(sql), 0o644)
	res := run(t, root)
	if len(res.Findings) != 0 || len(res.Warnings) != 1 || res.Warnings[0] != warnEventTrigger("supabase/migrations/1.sql") {
		t.Fatalf("%+v", res)
	}
}

func TestOversizeFileWarns(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "supabase", "migrations")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "big.sql"), make([]byte, maxFileSize+1), 0o644)
	os.WriteFile(filepath.Join(dir, "note.txt"), []byte("create table a (id int);"), 0o644)
	res := run(t, root)
	if len(res.Findings) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "big.sql") {
		t.Fatalf("%+v", res)
	}
}

func TestCancelled(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "supabase", "migrations")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "1.sql"), []byte("create table a (id int);"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(testData).Run(ctx, checker.Target{Root: root}); err == nil {
		t.Fatal("want error")
	}
}
