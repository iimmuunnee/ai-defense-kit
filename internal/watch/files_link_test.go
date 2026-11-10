package watch

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// makeDirLink makes link a directory link to target: a symbolic link, or on
// Windows without the right to make one, a junction.
func makeDirLink(t *testing.T, link, target string) bool {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return true
	}
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/c", "mklink", "/J", link, target).Run() == nil
	}
	return false
}

// A link at the parent directory of a watched file must not hide the file: the
// link is recorded by its target, and nothing behind it is read.
func TestRepoLinkAtParentOfWatchedFile(t *testing.T) {
	root := t.TempDir()
	put(t, root, "yarn.lock", "y")
	evil := filepath.Join(root, "evil")
	put(t, root, "evil/tasks.json", "outside-the-intent")
	opts := map[string]any{"root": root}
	base, err := observeRepo(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !makeDirLink(t, filepath.Join(root, ".vscode"), evil) {
		t.Skip("neither a symbolic link nor a junction can be made on this machine")
	}
	now, err := observeRepo(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	d := Diff("repo", base, now)
	if len(d) != 1 || d[0].Field != "file:.vscode" || !strings.HasPrefix(d[0].New, "symlink:") {
		t.Fatalf("diff = %v\nnow = %v", d, now)
	}
	if _, through := now["file:.vscode/tasks.json"]; through {
		t.Error("the file behind the link was read")
	}

	// Pointing the link somewhere else is a change.
	other := filepath.Join(root, "other")
	put(t, root, "other/x", "x")
	if err := os.Remove(filepath.Join(root, ".vscode")); err != nil {
		t.Fatal(err)
	}
	if !makeDirLink(t, filepath.Join(root, ".vscode"), other) {
		t.Fatal("could not make the second link")
	}
	again, err := observeRepo(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff("repo", now, again); len(d) != 1 || d[0].Field != "file:.vscode" {
		t.Errorf("retarget diff = %v", d)
	}
}

func TestCouldMatchBelow(t *testing.T) {
	for _, tc := range []struct {
		glob, dir string
		want      bool
	}{
		{".vscode/tasks.json", ".vscode", true},
		{".vscode/tasks.json", ".github", false},
		{".github/workflows/**", ".github", true},
		{".github/workflows/**", ".github/workflows", true},
		{".github/workflows/**", "docs", false},
		{"**/x.txt", "a/b", true},
		{"yarn.lock", "sub", false},
		{"a/*/c.txt", "a/b", true},
		{"a/*/c.txt", "a/b/c.txt", false},
		{"{a,b}/x", "a", true},
	} {
		if got := couldMatchBelow(tc.glob, tc.dir); got != tc.want {
			t.Errorf("couldMatchBelow(%q, %q) = %v, want %v", tc.glob, tc.dir, got, tc.want)
		}
	}
}
