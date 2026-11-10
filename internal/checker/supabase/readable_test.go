package supabase

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func migrations(t *testing.T, sql string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "supabase", "migrations")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0001.sql"), []byte(sql), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func throughRunAll(t *testing.T, root string) []finding.Finding {
	t.Helper()
	got, _ := checker.RunAll(context.Background(), []checker.Checker{New(testData)}, checker.Target{Root: root}, 0)
	return got
}

// I1: 제목은 도구가 만든 문장이라 단어 수를 세지 않는다. 테이블 이름만 따로 검사한다.
func TestTitleShowsLongTableName(t *testing.T) {
	got := throughRunAll(t, migrations(t, "create table public.order_item_refund_audit_log_entry (id int);\n"))
	if len(got) != 1 {
		t.Fatalf("findings = %d", len(got))
	}
	if got[0].Title != "RLS가 켜지지 않은 테이블: public.order_item_refund_audit_log_entry" || got[0].Evidence != "public.order_item_refund_audit_log_entry" {
		t.Errorf("title %q evidence %q", got[0].Title, got[0].Evidence)
	}
}

// 이름 자체가 단어 나열이면 그 이름은 가린다(대문자, 섞인 구분 문자도).
func TestPhraseShapedTableNameStaysHidden(t *testing.T) {
	var w []string
	for i := 0; i < 12; i++ {
		sum := sha256.Sum256([]byte("b3-sb" + string(rune('a'+i))))
		b := make([]byte, 6)
		for j := range b {
			b[j] = 'a' + sum[j]%26
		}
		w = append(w, string(b))
	}
	name := strings.Join(w[:6], "_") + "$" + strings.ToUpper(strings.Join(w[6:], "_"))
	got := throughRunAll(t, migrations(t, "create table public."+name+" (id int);\n"))
	if len(got) != 1 {
		t.Fatalf("findings = %d", len(got))
	}
	text := strings.ToLower(got[0].Title + " " + got[0].Evidence)
	for _, word := range w {
		if strings.Contains(text, word) {
			t.Errorf("word shown: %q", text)
			break
		}
	}
	if !strings.HasPrefix(got[0].Title, "RLS가 켜지지 않은 테이블: public.") {
		t.Errorf("title %q", got[0].Title)
	}
	if got[0].Fingerprint != finding.MakeFingerprint("SB-001", "supabase/migrations/0001.sql", "public."+name) {
		t.Errorf("fingerprint changed")
	}
}
