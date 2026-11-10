package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreParse(t *testing.T) {
	root := t.TempDir()
	body := "# 전체 주석\n\nabc123def4567890   # 뒤쪽 주석\n  \n\t0011223344556677\n"
	if err := os.WriteFile(filepath.Join(root, ".adkignore"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"abc123def4567890", "0011223344556677"} {
		if !s.Has(fp) {
			t.Errorf("Has(%q) = false", fp)
		}
	}
	for _, fp := range []string{"", "#", "전체", "abc123def456789"} {
		if s.Has(fp) {
			t.Errorf("Has(%q) = true", fp)
		}
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil || s.Has("anything") {
		t.Fatalf("err=%v", err)
	}
}

func TestLoadOtherErrorFails(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".adkignore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("expected error when .adkignore is a directory")
	}
}

// Windows Notepad may save .adkignore with a UTF-8 BOM.
func TestIgnoreStripsBOM(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".adkignore"), []byte("\xef\xbb\xbfabc123def4567890\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has("abc123def4567890") {
		t.Errorf("first fingerprint after BOM not loaded: %v", s)
	}
}
