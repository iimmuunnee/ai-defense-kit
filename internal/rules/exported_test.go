package rules

import "testing"

func TestSkipDirExported(t *testing.T) {
	for _, n := range []string{".git", "node_modules", ".next", "dist", "build", "vendor", ".venv", "__pycache__"} {
		if !SkipDir(n) {
			t.Errorf("SkipDir(%q) = false", n)
		}
	}
	for _, n := range []string{"src", ".vscode", ""} {
		if SkipDir(n) {
			t.Errorf("SkipDir(%q) = true", n)
		}
	}
}
