package watch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func put(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func repoTarget(opts map[string]any) Target {
	return Target{Key: "repo", Kind: kindRepo, Options: opts}
}

func observeRepo(t *testing.T, opts map[string]any) (Observation, error) {
	t.Helper()
	return NewRepoObserver().Observe(context.Background(), repoTarget(opts))
}

func TestRepoDefaultGlobs(t *testing.T) {
	root := t.TempDir()
	put(t, root, ".github/workflows/ci.yml", "ci")
	put(t, root, ".github/workflows/sub/deep.yml", "deep")
	put(t, root, ".vscode/tasks.json", "tasks")
	put(t, root, ".vscode/settings.json", "not watched")
	put(t, root, "package-lock.json", "npm")
	put(t, root, "pnpm-lock.yaml", "pnpm")
	put(t, root, "yarn.lock", "yarn")
	put(t, root, "composer.lock", "composer")
	put(t, root, "README.md", "not watched")
	put(t, root, ".git/config", "never")
	put(t, root, "sub/package-lock.json", "not at root")

	obs, err := observeRepo(t, map[string]any{"root": root})
	if err != nil {
		t.Fatal(err)
	}
	want := Observation{
		"root":                                filepath.ToSlash(root),
		"file:.github/workflows/ci.yml":       sum("ci"),
		"file:.github/workflows/sub/deep.yml": sum("deep"),
		"file:.vscode/tasks.json":             sum("tasks"),
		"file:package-lock.json":              sum("npm"),
		"file:pnpm-lock.yaml":                 sum("pnpm"),
		"file:yarn.lock":                      sum("yarn"),
		"file:composer.lock":                  sum("composer"),
	}
	if len(obs) != len(want) {
		t.Fatalf("obs = %v\nwant %v", obs, want)
	}
	for k, v := range want {
		if obs[k] != v {
			t.Errorf("%s = %q, want %q", k, obs[k], v)
		}
	}
}

func TestRepoRootIsCleanedAsWritten(t *testing.T) {
	root := t.TempDir()
	put(t, root, "yarn.lock", "y")
	put(t, root, "sub/x", "x")
	obs, err := observeRepo(t, map[string]any{"root": filepath.ToSlash(root) + "/sub/..//"})
	if err != nil {
		t.Fatal(err)
	}
	if obs["root"] != filepath.ToSlash(root) {
		t.Errorf("root = %q, want %q", obs["root"], filepath.ToSlash(root))
	}
	if obs["file:yarn.lock"] != sum("y") {
		t.Errorf("obs = %v", obs)
	}
}

func TestRepoDoubleStarAndCustomGlobs(t *testing.T) {
	root := t.TempDir()
	put(t, root, "a/b/c/x.txt", "x")
	put(t, root, "x.txt", "top")
	put(t, root, "a/y.md", "md")
	obs, err := observeRepo(t, map[string]any{"root": root, "globs": []any{"**/x.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if obs["file:a/b/c/x.txt"] != sum("x") || obs["file:x.txt"] != sum("top") || len(obs) != 3 {
		t.Errorf("obs = %v", obs)
	}
	// Fields use forward slashes on every OS.
	for k := range obs {
		if strings.Contains(k, "\\") {
			t.Errorf("backslash in %q", k)
		}
	}
}

func TestRepoChangeAddDelete(t *testing.T) {
	root := t.TempDir()
	put(t, root, "yarn.lock", "1")
	opts := map[string]any{"root": root}
	a, err := observeRepo(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	put(t, root, "yarn.lock", "2")
	put(t, root, "pnpm-lock.yaml", "new")
	b, _ := observeRepo(t, opts)
	if d := Diff("repo", a, b); len(d) != 2 {
		t.Errorf("diff = %v", d)
	}
	_ = os.Remove(filepath.Join(root, "yarn.lock"))
	_ = os.Remove(filepath.Join(root, "pnpm-lock.yaml"))
	c, err := observeRepo(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	d := Diff("repo", a, c)
	if len(d) != 1 || d[0].Field != "file:yarn.lock" || d[0].New != "" {
		t.Errorf("diff = %v", d)
	}
	if err := CheckInitial(repoTarget(opts), c); err == nil {
		t.Error("a root matching nothing passed CheckInitial")
	}
	if err := CheckInitial(repoTarget(opts), a); err != nil {
		t.Errorf("CheckInitial = %v", err)
	}
}

func TestRepoMissingRootIsPlainError(t *testing.T) {
	obs, err := observeRepo(t, map[string]any{"root": filepath.Join(t.TempDir(), "nope")})
	var pe PartialError
	if err == nil || obs != nil || errors.As(err, &pe) {
		t.Errorf("obs=%v err=%v", obs, err)
	}
	f := filepath.Join(t.TempDir(), "afile")
	if e := os.WriteFile(f, nil, 0o600); e != nil {
		t.Fatal(e)
	}
	if _, err := observeRepo(t, map[string]any{"root": f}); err == nil {
		t.Error("a file as root was accepted")
	}
}

func TestRepoUnreadableFileIsPartial(t *testing.T) {
	root := t.TempDir()
	put(t, root, "yarn.lock", "y")
	put(t, root, "pnpm-lock.yaml", "p")
	o := &repoObserver{open: func(p string) (io.ReadCloser, error) {
		if strings.HasSuffix(filepath.ToSlash(p), "pnpm-lock.yaml") {
			return nil, errors.New("denied")
		}
		return os.Open(p)
	}}
	obs, err := o.Observe(context.Background(), repoTarget(map[string]any{"root": root}))
	var pe PartialError
	if !errors.As(err, &pe) || obs != nil {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	if pe.Obs["file:yarn.lock"] != sum("y") {
		t.Errorf("partial = %v", pe.Obs)
	}
	if _, has := pe.Obs["file:pnpm-lock.yaml"]; has {
		t.Error("an unreadable file was recorded")
	}
	if !strings.Contains(err.Error(), "pnpm-lock.yaml") {
		t.Errorf("error does not say which file: %v", err)
	}
}

func TestRepoSymlinkIsRecordedByTarget(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	put(t, outside, "secret.txt", "outside-v1")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "yarn.lock")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("no symlink permission: %v", err)
		}
		t.Fatal(err)
	}
	// A directory link that leaves the root must not be walked either.
	put(t, outside, "workflows/evil.yml", "e1")
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "workflows"), filepath.Join(root, ".github", "workflows")); err != nil {
		t.Fatal(err)
	}
	opts := map[string]any{"root": root}
	a, err := observeRepo(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	for k := range a {
		if strings.Contains(k, "evil") {
			t.Errorf("walked through a directory link: %v", a)
		}
	}
	if a["file:yarn.lock"] == sum("outside-v1") || a["file:yarn.lock"] == "" {
		t.Errorf("symlink value = %q (content of the target must not be read)", a["file:yarn.lock"])
	}
	put(t, outside, "secret.txt", "outside-v2")
	b, _ := observeRepo(t, opts)
	if d := Diff("repo", a, b); len(d) != 0 {
		t.Errorf("a change outside root was seen: %v", d)
	}
	// Pointing the link elsewhere is a change.
	_ = os.Remove(filepath.Join(root, "yarn.lock"))
	if err := os.Symlink(filepath.Join(outside, "other.txt"), filepath.Join(root, "yarn.lock")); err != nil {
		t.Fatal(err)
	}
	c, _ := observeRepo(t, opts)
	if d := Diff("repo", a, c); len(d) != 1 {
		t.Errorf("diff = %v", d)
	}
}

func TestRepoHashesLargeFilesWithoutLimit(t *testing.T) {
	root := t.TempDir()
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<20) // 16 MiB
	if err := os.WriteFile(filepath.Join(root, "yarn.lock"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := observeRepo(t, map[string]any{"root": root})
	if err != nil {
		t.Fatal(err)
	}
	if obs["file:yarn.lock"] != sum(string(big)) {
		t.Error("large file hash differs")
	}
}

func TestRepoOptionErrors(t *testing.T) {
	for name, opts := range map[string]map[string]any{
		"no root":        {},
		"root not text":  {"root": 5},
		"empty root":     {"root": " "},
		"unknown option": {"root": ".", "glob": []any{"*"}},
		"bad glob":       {"root": ".", "globs": []any{"["}},
		"glob not text":  {"root": ".", "globs": []any{5}},
		"globs not list": {"root": ".", "globs": "*"},
		"empty globs":    {"root": ".", "globs": []any{}},
		"absolute glob":  {"root": ".", "globs": []any{"/etc/passwd"}},
		"dotdot glob":    {"root": ".", "globs": []any{"../x"}},
		"dotdot inside":  {"root": ".", "globs": []any{"a/../../x"}},
	} {
		if err := validateRepoOptions(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := observeRepo(t, opts); err == nil {
			t.Errorf("%s: observe accepted", name)
		}
	}
}
