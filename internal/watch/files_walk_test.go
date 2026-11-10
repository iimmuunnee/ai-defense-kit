package watch

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// walkRecorder walks the real tree, notes every directory the observer goes
// into, and reports a read failure for the directories named in unreadable, the
// way filepath.WalkDir does: a second call with the error.
func walkRecorder(entered *[]string, unreadable ...string) func(string, fs.WalkDirFunc) error {
	return func(root string, fn fs.WalkDirFunc) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			r := fn(p, d, err)
			if r != nil || !d.IsDir() {
				return r
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			*entered = append(*entered, rel)
			if slices.Contains(unreadable, rel) {
				if r := fn(p, d, fs.ErrPermission); r != nil {
					return r
				}
				return filepath.SkipDir
			}
			return nil
		})
	}
}

func TestRepoDoesNotGoWhereNoGlobCanMatch(t *testing.T) {
	root := t.TempDir()
	put(t, root, "yarn.lock", "y")
	put(t, root, ".github/workflows/ci.yml", "c")
	put(t, root, "src/deep/a.txt", "a")
	put(t, root, "locked/secret.txt", "s")
	var entered []string
	o := &repoObserver{walk: walkRecorder(&entered, "locked")}
	obs, err := o.Observe(context.Background(), repoTarget(map[string]any{"root": root}))
	if err != nil {
		t.Fatalf("a directory no glob can reach decided the result: %v", err)
	}
	if obs["file:yarn.lock"] != sum("y") || obs["file:.github/workflows/ci.yml"] != sum("c") {
		t.Errorf("obs = %v", obs)
	}
	for _, d := range []string{"src", "src/deep", "locked"} {
		if slices.Contains(entered, d) {
			t.Errorf("went into %s (entered %v)", d, entered)
		}
	}
}

// A directory a glob can reach is still a real gap.
func TestRepoUnreadableDirectoryUnderAGlobStaysPartial(t *testing.T) {
	root := t.TempDir()
	put(t, root, "a.yml", "a")
	put(t, root, "locked/b.yml", "b")
	var entered []string
	o := &repoObserver{walk: walkRecorder(&entered, "locked")}
	_, err := o.Observe(context.Background(), repoTarget(map[string]any{"root": root, "globs": []any{"**/*.yml"}}))
	var pe PartialError
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "locked") {
		t.Errorf("err = %v", err)
	}
}

func TestCouldMatchBelowSaysYesWhenInDoubt(t *testing.T) {
	for _, c := range []struct{ glob, dir string }{
		{`src\/x.yml`, "src"},
		{`s[/]c/x.yml`, "s"},
		{`{src,lib}/x.yml`, "src"},
	} {
		if !couldMatchBelow(c.glob, c.dir) {
			t.Errorf("couldMatchBelow(%q, %q) = false", c.glob, c.dir)
		}
	}
}

func TestRepoSkipsNodeModules(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package-lock.json", "top")
	put(t, root, "packages/a/package-lock.json", "a")
	put(t, root, "node_modules/dep/package-lock.json", "x")
	put(t, root, "packages/a/node_modules/dep/package-lock.json", "y")
	makeDirLink(t, filepath.Join(root, "node_modules", "linked"), filepath.Join(root, "packages"))
	var entered []string
	o := &repoObserver{walk: walkRecorder(&entered)}
	obs, err := o.Observe(context.Background(), repoTarget(map[string]any{"root": root, "globs": []any{"**/package-lock.json"}}))
	if err != nil {
		t.Fatal(err)
	}
	if obs["file:package-lock.json"] != sum("top") || obs["file:packages/a/package-lock.json"] != sum("a") {
		t.Errorf("a lock file outside node_modules was not read: %v", obs)
	}
	for k := range obs {
		if strings.Contains(k, "node_modules") {
			t.Errorf("recorded %s", k)
		}
	}
	for _, d := range entered {
		if strings.Contains(d, "node_modules") {
			t.Errorf("went into %s", d)
		}
	}
}

func TestRepoNodeModulesNamedByAGlob(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package-lock.json", "top")
	put(t, root, "node_modules/dep/package.json", "d")
	put(t, root, "node_modules/dep/package-lock.json", "x")
	put(t, root, "node_modules/other/package.json", "o")
	obs, err := observeRepo(t, map[string]any{"root": root, "globs": []any{"node_modules/dep/package.json", "**/package-lock.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if obs["file:node_modules/dep/package.json"] != sum("d") {
		t.Errorf("the named file was not read: %v", obs)
	}
	if _, has := obs["file:node_modules/dep/package-lock.json"]; has {
		t.Errorf("a glob that does not name node_modules reached into it: %v", obs)
	}
	if _, has := obs["file:node_modules/other/package.json"]; has {
		t.Errorf("read more than named: %v", obs)
	}
}

// M1: such a glob would be accepted and never read.
func TestRepoGlobUnderGitIsRefused(t *testing.T) {
	for _, g := range []string{".git/hooks/*", "./.git/config", "sub/.git/config", "**/.git/hooks/*", ".git", ".git/**"} {
		err := validateRepoOptions(map[string]any{"root": ".", "globs": []any{g}})
		if err == nil || !strings.Contains(err.Error(), ".git") {
			t.Errorf("%s: err = %v", g, err)
		}
	}
	for _, g := range []string{".github/workflows/*", ".gitignore", "a/.gitmodules", ".gitlab-ci.yml"} {
		if err := validateRepoOptions(map[string]any{"root": ".", "globs": []any{g}}); err != nil {
			t.Errorf("%s: %v", g, err)
		}
	}
}

func TestRepoWalkLimitsAreDocumented(t *testing.T) {
	s := readText(t, "../../docs/watch.md")
	for _, want := range []string{"`node_modules`", "`.git/` 안을 가리키는 패턴은 거부", "들어가지 않으므로"} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
}
