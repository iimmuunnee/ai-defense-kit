package supabase

import (
	"reflect"
	"strings"
	"testing"
)

func names(ts []Table) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestFindTablesWithoutRLS(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{"basic create", []string{`create table public.a (id int);`}, []string{"a"}},
		{"if not exists and quoted", []string{`create table if not exists public."Quoted" (id int);`}, []string{"Quoted"}},
		{"schema omitted", []string{`create table a (id int);`}, []string{"a"}},
		{"other schema", []string{`create table private.x (id int);`}, nil},
		{"enable same file", []string{"create table public.a (id int);\nalter table public.a enable row level security;"}, nil},
		{"enable next file", []string{`create table public.a (id int);`, `alter table public.a enable row level security;`}, nil},
		{"enable then disable", []string{"create table public.a (id int);\nalter table public.a enable row level security;\nalter table public.a disable row level security;"}, []string{"a"}},
		{"disable then enable", []string{"create table public.a (id int);\nalter table public.a disable row level security;\nalter table public.a enable row level security;"}, nil},
		{"alter only", []string{"create table public.a (id int);\nalter table only public.a enable row level security;"}, nil},
		{"alter if exists", []string{"create table public.a (id int);\nalter table if exists public.a enable row level security;"}, nil},
		{"commented line enable", []string{"create table public.a (id int);\n-- alter table public.a enable row level security;"}, []string{"a"}},
		{"commented block enable", []string{"create table public.a (id int);\n/* alter table public.a\n enable row level security; */"}, []string{"a"}},
		{"drop", []string{"create table public.a (id int);\ndrop table public.a;"}, nil},
		{"drop if exists list", []string{"create table public.a (id int);\ncreate table public.b (id int);\ndrop table if exists public.a, b cascade;"}, nil},
		{"recreate after drop", []string{"create table public.a (id int);\nalter table public.a enable row level security;\ndrop table public.a;\ncreate table public.a (id int);"}, []string{"a"}},
		{"uppercase", []string{"CREATE TABLE PUBLIC.A (id int);\nALTER TABLE PUBLIC.A ENABLE ROW LEVEL SECURITY;"}, nil},
		{"uppercase unprotected", []string{"CREATE TABLE IF NOT EXISTS A (id int);"}, []string{"A"}},
		{"quoted case sensitive", []string{"create table public.\"Foo\" (id int);\nalter table public.foo enable row level security;"}, []string{"Foo"}},
		{"quoted equals unquoted lower", []string{"create table public.foo (id int);\nalter table public.\"foo\" enable row level security;"}, nil},
		{"quoted public schema", []string{"create table \"public\".a (id int);"}, []string{"a"}},
		{"partition of", []string{"create table public.p1 partition of public.p for values in (1);"}, []string{"p1"}},
		{"unlogged", []string{"create unlogged table public.u (id int);"}, []string{"u"}},
		{"temp skipped", []string{"create temp table t (id int);\ncreate temporary table public.t2 (id int);\ncreate global temporary table t3 (id int);"}, nil},
		{"string literal create", []string{`select 'create table public.fake (id int)';`}, nil},
		{"function body create", []string{"create or replace function f() returns void as $$ begin execute 'create table public.dyn(id int)'; end $$ language plpgsql;"}, nil},
		{"function body bare create", []string{"create function f() returns void as $fn$ begin create table public.dyn(id int); end $fn$ language plpgsql;"}, nil},
		{"do block create", []string{"do $$ begin create table public.d(id int); end $$;"}, []string{"d"}},
		{"do block enable", []string{"create table public.d(id int);\ndo $$ begin alter table public.d enable row level security; end $$;"}, nil},
		{"do block dynamic string ignored", []string{"do $$ begin execute 'create table public.d(id int)'; end $$;"}, nil},
		{"rename then enable new", []string{"create table public.a (id int);\nalter table public.a rename to b;\nalter table public.b enable row level security;"}, nil},
		{"rename keeps state", []string{"create table public.a (id int);\nalter table if exists only public.a rename to \"B\";"}, []string{"B"}},
		{"rename of enabled stays enabled", []string{"create table public.a (id int);\nalter table public.a enable row level security;\nalter table public.a rename to b;"}, nil},
		{"rename column is not rename", []string{"create table public.a (id int);\nalter table public.a rename column x to y;"}, []string{"a"}},
		{"set schema private", []string{"create table public.a (id int);\nalter table public.a set schema private;"}, nil},
		{"combined alter enable", []string{"create table public.a (id int);\nalter table public.a add column x int, enable row level security;"}, nil},
		{"combined alter enable first", []string{"create table public.a (id int);\nalter table public.a\n  enable row level security,\n  add column x int;"}, nil},
		{"combined alter disable", []string{"create table public.a (id int);\nalter table public.a enable row level security;\nalter table public.a add column x int, disable row level security;"}, []string{"a"}},
		{"apostrophe in dollar body", []string{"create function f() returns text as $$ it's fine -- not a comment $$ language sql;\ncreate table public.a (id int);"}, []string{"a"}},
		{"two tables one protected", []string{"create table public.a (id int);\ncreate table public.b (id int);\nalter table public.a enable row level security;"}, []string{"b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var files []SQLFile
			for i, c := range tc.files {
				files = append(files, SQLFile{Path: "m" + string(rune('a'+i)) + ".sql", Content: c})
			}
			got, warns := Analyze(files)
			if !reflect.DeepEqual(names(got), tc.want) {
				t.Errorf("tables = %v, want %v", names(got), tc.want)
			}
			if len(warns) != 0 {
				t.Errorf("warnings = %v", warns)
			}
			if !reflect.DeepEqual(names(FindTablesWithoutRLS(files)), tc.want) {
				t.Errorf("FindTablesWithoutRLS differs from Analyze")
			}
		})
	}
}

func TestEventTriggerSkips(t *testing.T) {
	files := []SQLFile{
		{Path: "a.sql", Content: "create table public.a (id int);"},
		{Path: "b.sql", Content: "create function rls_auto() returns event_trigger as $$ begin execute 'alter table x enable row level security'; end $$ language plpgsql;\ncreate event trigger t on ddl_command_end execute function rls_auto();"},
	}
	got, warns := Analyze(files)
	if len(got) != 0 {
		t.Errorf("tables = %v, want none", got)
	}
	if len(warns) != 1 || warns[0] != warnEventTrigger("b.sql") {
		t.Errorf("warnings = %v", warns)
	}
}

func TestEventTriggerCommentedDoesNotSkip(t *testing.T) {
	files := []SQLFile{{Path: "a.sql", Content: "create table public.a (id int);\n-- create event trigger t; enable row level security"}}
	got, warns := Analyze(files)
	if len(got) != 1 || len(warns) != 0 {
		t.Errorf("tables = %v warnings = %v", got, warns)
	}
}

func TestLineAndFile(t *testing.T) {
	content := "-- c1\n/* block\n   comment */\n\ncreate table public.a (\n id int\n);\n"
	got := FindTablesWithoutRLS([]SQLFile{{Path: "supabase/migrations/x.sql", Content: content}})
	if len(got) != 1 || got[0].Line != 5 || got[0].File != "supabase/migrations/x.sql" {
		t.Fatalf("got %+v", got)
	}
}

func TestCommentMarkersInStringsAreKept(t *testing.T) {
	content := "insert into t values ('--');\ncreate table public.a (d text default '/*');\nalter table public.a enable row level security;"
	if got := FindTablesWithoutRLS([]SQLFile{{Path: "x.sql", Content: content}}); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestMaskKeepsOffsets(t *testing.T) {
	in := "a -- x\nb /* y\nz */ c 'q\nr' $$ s\nt $$"
	out := mask(in, true)
	if len(out) != len(in) {
		t.Fatalf("length changed: %q", out)
	}
	for i := range in {
		if in[i] == '\n' && out[i] != '\n' {
			t.Errorf("newline lost at %d", i)
		}
	}
}

func TestApostropheInDollarBodyDoesNotDesync(t *testing.T) {
	// after the body, a real comment and a real enable must still be seen correctly
	content := "create table public.a (id int);\ncreate function f() returns text as $$ it's fine -- not a comment $$ language sql;\nalter table public.a enable row level security; -- it's done\ncreate table public.b (id int);"
	got := FindTablesWithoutRLS([]SQLFile{{Path: "x.sql", Content: content}})
	if !reflect.DeepEqual(names(got), []string{"b"}) {
		t.Errorf("got %v", names(got))
	}
}

func TestRenameKeepsCreateLocation(t *testing.T) {
	files := []SQLFile{
		{Path: "1.sql", Content: "\ncreate table public.a (id int);"},
		{Path: "2.sql", Content: "alter table public.a rename to b;"},
	}
	got := FindTablesWithoutRLS(files)
	if len(got) != 1 || got[0].Name != "b" || got[0].File != "1.sql" || got[0].Line != 2 {
		t.Errorf("got %+v", got)
	}
}

// RLS enabled by dynamic SQL in a do block is treated like the
// event-trigger case: no per-table findings, one warning naming the file.
func TestDoBlockDynamicEnableSkips(t *testing.T) {
	files := []SQLFile{
		{Path: "a.sql", Content: "create table public.a (id int);\ncreate table public.b (id int);"},
		{Path: "b.sql", Content: "do $$\ndeclare t text;\nbegin\n  for t in select tablename from pg_tables where schemaname = 'public' loop\n    execute format('alter table public.%I enable row level security', t);\n  end loop;\nend\n$$;"},
	}
	got, warns := Analyze(files)
	if len(got) != 0 {
		t.Errorf("tables = %v, want none", got)
	}
	if len(warns) != 1 || warns[0] != warnDynamicEnable("b.sql") || !strings.Contains(warns[0], "b.sql") || !strings.Contains(warns[0], "모든 테이블") {
		t.Errorf("warnings = %v", warns)
	}
}

// A function body (not run at migration time) with dynamic enable does not skip.
func TestFunctionDynamicEnableDoesNotSkip(t *testing.T) {
	files := []SQLFile{{Path: "a.sql", Content: "create table public.a (id int);\ncreate function f(t text) returns void as $$ begin execute format('alter table %I enable row level security', t); end $$ language plpgsql;"}}
	got, warns := Analyze(files)
	if len(got) != 1 || len(warns) != 0 {
		t.Errorf("tables = %v warnings = %v", got, warns)
	}
}
