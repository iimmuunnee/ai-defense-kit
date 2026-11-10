package device

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("tools and persistence points are not compared on Windows")
	}
}

// script writes a harmless executable shell script.
func script(t *testing.T, path, word string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+word+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// relink points path at target, replacing what was there.
func relink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func observe(t *testing.T, o Options) Snapshot {
	t.Helper()
	return Observe(context.Background(), o)
}

func ids(fs []finding.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.ID+"/"+f.Severity.String()]++
	}
	return m
}

func TestToolsFirstInPath(t *testing.T) {
	skipWindows(t)
	home, a, b := t.TempDir(), t.TempDir(), t.TempDir()
	// Not executable in a: the shell skips it, so must we.
	write(t, filepath.Join(a, "pyenv"), "#!/bin/sh\necho no\n")
	script(t, filepath.Join(b, "pyenv"), "ok")
	script(t, filepath.Join(b, "notatool"), "ok")
	snap := observe(t, Options{Home: home, Path: a + string(os.PathListSeparator) + b, Getenv: envOf(nil)})
	obs, ok := snap.Entries["tool:pyenv"]
	if !ok {
		t.Fatalf("pyenv not observed: %v", snap.Entries)
	}
	if obs["entry"] != filepath.ToSlash(filepath.Join(b, "pyenv")) || obs["kind"] != "file" || len(obs["sha256"]) != 64 {
		t.Errorf("obs = %v", obs)
	}
	for k := range snap.Entries {
		if strings.HasPrefix(k, "tool:") && k != "tool:pyenv" {
			t.Errorf("unexpected %s", k)
		}
	}
	if len(snap.Unread) != 0 || len(InitFindings(snap, Options{Home: home})) != 0 {
		t.Errorf("unread=%v", snap.Unread)
	}
}

func TestToolChanged(t *testing.T) {
	skipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	script(t, filepath.Join(bin, "pyenv"), "ok")
	base := observe(t, o).Entries
	script(t, filepath.Join(bin, "pyenv"), "changed")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || fs[0].ID != "DV-101" || fs[0].Severity < finding.High || fs[0].Location != "tool:pyenv" {
		t.Fatalf("findings = %+v", fs)
	}
	if fs[0].ExplainKo == "" || fs[0].Fix == "" {
		t.Errorf("explain or fix missing")
	}
	if fs := Compare(base, Snapshot{Entries: base}, o); len(fs) != 0 {
		t.Errorf("same snapshot: %+v", fs)
	}
}

func TestToolAppearsAndDisappears(t *testing.T) {
	skipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	base := observe(t, o).Entries
	if len(base) != 0 {
		t.Fatalf("empty PATH observed %v", base)
	}
	// Missing at init and still missing: nothing.
	if fs := Compare(base, observe(t, o), o); len(fs) != 0 {
		t.Errorf("missing twice: %+v", fs)
	}
	script(t, filepath.Join(bin, "git"), "ok")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || fs[0].ID != "DV-101" || fs[0].Severity != finding.High || !strings.Contains(fs[0].Evidence, "새로") {
		t.Fatalf("appeared: %+v", fs)
	}
	base = observe(t, o).Entries
	if err := os.Remove(filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	fs = Compare(base, observe(t, o), o)
	if len(fs) != 1 || fs[0].ID != "DV-101" || fs[0].Severity != finding.High || !strings.Contains(fs[0].Evidence, "사라") {
		t.Fatalf("removed: %+v", fs)
	}
}

// cellar lays out a fake Homebrew prefix with tools at version v.
func cellar(t *testing.T, prefix, v string, tools ...string) {
	t.Helper()
	for _, name := range tools {
		target := filepath.Join(prefix, "Cellar", name, v, "bin", name)
		script(t, target, name+" "+v)
		relink(t, filepath.Join("..", "Cellar", name, v, "bin", name), filepath.Join(prefix, "bin", name))
	}
}

func TestUpgradeGrouped(t *testing.T) {
	skipWindows(t)
	home, prefix := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: filepath.Join(prefix, "bin"), Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": prefix})}
	cellar(t, prefix, "1.0.0", "node", "git")
	snap := observe(t, o)
	if len(InitFindings(snap, o)) != 0 {
		t.Fatalf("Cellar links reported as outside: %+v", InitFindings(snap, o))
	}
	base := snap.Entries
	if base["tool:node"]["kind"] != "link" || !strings.Contains(base["tool:node"]["target"], "/Cellar/node/1.0.0/bin/node") {
		t.Fatalf("node = %v", base["tool:node"])
	}
	cellar(t, prefix, "1.1.0", "node", "git")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %+v", fs)
	}
	f := fs[0]
	if f.ID != "DV-101" || f.Severity != finding.Medium {
		t.Errorf("finding = %+v", f)
	}
	for _, want := range []string{"tool:node", "tool:git", "1.0.0", "1.1.0"} {
		if !strings.Contains(f.Evidence+f.Location, want) {
			t.Errorf("grouped finding lacks %q: %+v", want, f)
		}
	}
}

func TestUpgradeShapeOnly(t *testing.T) {
	skipWindows(t)
	home, prefix := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: filepath.Join(prefix, "bin"), Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": prefix})}
	cellar(t, prefix, "1.0.0", "node")
	base := observe(t, o).Entries

	// A version folder name that is not a version.
	script(t, filepath.Join(prefix, "Cellar", "node", "evil", "bin", "node"), "x")
	relink(t, filepath.Join("..", "Cellar", "node", "evil", "bin", "node"), filepath.Join(prefix, "bin", "node"))
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || fs[0].Severity != finding.High {
		t.Errorf("non-version folder: %+v", fs)
	}
	// Another formula's folder.
	script(t, filepath.Join(prefix, "Cellar", "other", "1.1.0", "bin", "node"), "x")
	relink(t, filepath.Join("..", "Cellar", "other", "1.1.0", "bin", "node"), filepath.Join(prefix, "bin", "node"))
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || fs[0].Severity != finding.High {
		t.Errorf("other formula: %+v", fs)
	}
	// Same version path, different content.
	script(t, filepath.Join(prefix, "Cellar", "node", "1.0.0", "bin", "node"), "tampered")
	relink(t, filepath.Join("..", "Cellar", "node", "1.0.0", "bin", "node"), filepath.Join(prefix, "bin", "node"))
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || fs[0].Severity != finding.High {
		t.Errorf("content only: %+v", fs)
	}
	// A version path outside any Cellar.
	other := t.TempDir()
	script(t, filepath.Join(other, "node", "1.1.0", "bin", "node"), "x")
	relink(t, filepath.Join(other, "node", "1.1.0", "bin", "node"), filepath.Join(prefix, "bin", "node"))
	// The link leaves the Homebrew tree: DV-102 takes the place of DV-101.
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-102/high"] != 1 {
		t.Errorf("outside Cellar: %+v", fs)
	}
	// Version-looking folders that Homebrew does not make.
	for _, v := range []string{"1.1.0-x", "v1.1.0", "1.1.0.rc1", "1-a"} {
		script(t, filepath.Join(prefix, "Cellar", "node", v, "bin", "node"), "x")
		relink(t, filepath.Join("..", "Cellar", "node", v, "bin", "node"), filepath.Join(prefix, "bin", "node"))
		if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/high"] != 1 {
			t.Errorf("%s: %+v", v, fs)
		}
	}
	// A Homebrew revision suffix is an upgrade.
	script(t, filepath.Join(prefix, "Cellar", "node", "1.0.0_1", "bin", "node"), "x")
	relink(t, filepath.Join("..", "Cellar", "node", "1.0.0_1", "bin", "node"), filepath.Join(prefix, "bin", "node"))
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 {
		t.Errorf("revision suffix: %+v", fs)
	}
}

// pyenvTool lays out ~/.pyenv/versions/<v>/bin/python3 and links bin/python3 to it.
func pyenvTool(t *testing.T, home, bin, v string) {
	t.Helper()
	target := filepath.Join(home, ".pyenv", "versions", v, "bin", "python3")
	script(t, target, "python "+v)
	relink(t, target, filepath.Join(bin, "python3"))
}

func TestPyenvVersions(t *testing.T) {
	skipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	pyenvTool(t, home, bin, "3.12.4")
	base := observe(t, o).Entries
	for _, v := range []string{"3.13.0", "3.13.0t", "3.13.0a1", "3.13.0b2", "3.13.0rc1", "3.14-dev"} {
		pyenvTool(t, home, bin, v)
		if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 {
			t.Errorf("%s: %+v", v, fs)
		}
	}
	for _, v := range []string{"3.12.4-evil", "3.12.4_1", "pypy3.10-7.3.15"} {
		pyenvTool(t, home, bin, v)
		if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/high"] != 1 {
			t.Errorf("%s: %+v", v, fs)
		}
	}
}

// A version folder that is a link to a folder outside the root is not an
// upgrade, though the link text stays inside it.
func TestPyenvVersionFolderLink(t *testing.T) {
	skipWindows(t)
	home, bin, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	pyenvTool(t, home, bin, "3.12.4")
	base := observe(t, o).Entries
	script(t, filepath.Join(elsewhere, "bin", "python3"), "payload")
	relink(t, elsewhere, filepath.Join(home, ".pyenv", "versions", "9.9.9"))
	relink(t, filepath.Join(home, ".pyenv", "versions", "9.9.9", "bin", "python3"), filepath.Join(bin, "python3"))
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || ids(fs)["DV-101/high"] != 1 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestCellarVersionFolderLink(t *testing.T) {
	skipWindows(t)
	home, prefix, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: filepath.Join(prefix, "bin"), Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": prefix})}
	cellar(t, prefix, "22.1.0", "node")
	base := observe(t, o).Entries
	script(t, filepath.Join(elsewhere, "bin", "node"), "payload")
	relink(t, elsewhere, filepath.Join(prefix, "Cellar", "node", "99"))
	relink(t, filepath.Join("..", "Cellar", "node", "99", "bin", "node"), filepath.Join(prefix, "bin", "node"))
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || ids(fs)["DV-102/high"] != 1 {
		t.Fatalf("findings = %+v", fs)
	}
}

// A link whose text stays in the Cellar but whose folder leads outside it.
func TestFolderLinkOutside(t *testing.T) {
	skipWindows(t)
	home, prefix, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: filepath.Join(prefix, "bin"), Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": prefix})}
	script(t, filepath.Join(elsewhere, "bin", "gh"), "payload")
	relink(t, elsewhere, filepath.Join(prefix, "Cellar", "gh", "1.0"))
	relink(t, filepath.Join("..", "Cellar", "gh", "1.0", "bin", "gh"), filepath.Join(prefix, "bin", "gh"))
	init := InitFindings(observe(t, o), o)
	if len(init) != 1 || init[0].ID != "DV-102" {
		t.Fatalf("init findings = %+v", init)
	}
}

// realTempDir is t.TempDir() with its folder links resolved: on macOS the
// temp root is under /var, itself a link, which would add a hop to every
// absolute link target.
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestHopLimit(t *testing.T) {
	if hopLimit("darwin") != 32 || hopLimit("linux") != 40 {
		t.Errorf("darwin %d, linux %d", hopLimit("darwin"), hopLimit("linux"))
	}
}

// The kernel follows a fixed number of links in a row (Linux 40, macOS 32);
// a chain of exactly that many is observed.
func TestChainAtKernelLimit(t *testing.T) {
	skipWindows(t)
	home, bin, links := realTempDir(t), realTempDir(t), realTempDir(t)
	script(t, filepath.Join(links, "real"), "ok")
	prev := filepath.Join(links, "real")
	for i := range maxHops - 1 {
		p := filepath.Join(links, "l"+strconv.Itoa(i))
		relink(t, prev, p)
		prev = p
	}
	relink(t, prev, filepath.Join(bin, "npm")) // maxHops links in all
	snap := observe(t, Options{Home: home, Path: bin, Getenv: envOf(nil)})
	if _, ok := snap.Entries["tool:npm"]; !ok || len(snap.Unread) != 0 {
		t.Fatalf("entries=%v unread=%v", snap.Entries, snap.Unread)
	}
}

// A plain file that moved to another PATH folder is not a link change.
func TestPlainMoveWording(t *testing.T) {
	skipWindows(t)
	home, late, early := t.TempDir(), t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: early + string(os.PathListSeparator) + late, Getenv: envOf(nil)}
	script(t, filepath.Join(late, "git"), "ok")
	base := observe(t, o).Entries
	script(t, filepath.Join(early, "git"), "ok")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || !strings.Contains(fs[0].Evidence, "진입 경로") || strings.Contains(fs[0].Evidence, "링크") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestLinkOutside(t *testing.T) {
	skipWindows(t)
	home, prefix, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755); err != nil {
		t.Fatal(err)
	}
	o := Options{Home: home, Path: filepath.Join(prefix, "bin"), Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": prefix})}
	script(t, filepath.Join(elsewhere, "gh"), "ok")
	relink(t, filepath.Join(elsewhere, "gh"), filepath.Join(prefix, "bin", "gh"))
	snap := observe(t, o)
	// At init an outside link is a medium review item.
	init := InitFindings(snap, o)
	if len(init) != 1 {
		t.Fatalf("init findings = %+v", init)
	}
	f := init[0]
	if f.ID != "DV-102" || f.Severity != finding.Medium || f.Location != "tool:gh" || f.ExplainKo == "" || f.Fix == "" {
		t.Errorf("finding = %+v", f)
	}
	base := snap.Entries
	// Unchanged and in the baseline: nothing.
	if fs := Compare(base, observe(t, o), o); len(fs) != 0 {
		t.Errorf("unchanged check: %+v", fs)
	}
	// Retargeted to another outside file: DV-102 high, and only that.
	script(t, filepath.Join(elsewhere, "gh2"), "other")
	relink(t, filepath.Join(elsewhere, "gh2"), filepath.Join(prefix, "bin", "gh"))
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-102/high"] != 1 {
		t.Errorf("retargeted: %+v", fs)
	}
	// New since init: DV-102 high.
	if fs := Compare(map[string]watch.Observation{}, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-102/high"] != 1 {
		t.Errorf("new outside link: %+v", fs)
	}
	// Links into opt, Caskroom and the Homebrew folder itself are Homebrew's.
	for _, sub := range []string{"opt", "Caskroom", "Homebrew"} {
		script(t, filepath.Join(prefix, sub, "gh", "bin", "gh"), "ok")
		relink(t, filepath.Join("..", sub, "gh", "bin", "gh"), filepath.Join(prefix, "bin", "gh"))
		if s := InitFindings(observe(t, o), o); len(s) != 0 {
			t.Errorf("%s: %+v", sub, s)
		}
	}
	// Not a Homebrew prefix (no Cellar, no bin/brew): not DV-102.
	plain := t.TempDir()
	relink(t, filepath.Join(elsewhere, "gh"), filepath.Join(plain, "bin", "gh"))
	po := Options{Home: home, Path: filepath.Join(plain, "bin"), Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": plain})}
	if s := InitFindings(observe(t, po), po); len(s) != 0 {
		t.Errorf("plain folder: %+v", s)
	}
}

func TestToolUnreadable(t *testing.T) {
	skipWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home, bin := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	p := filepath.Join(bin, "kubectl")
	script(t, p, "ok")
	base := observe(t, o).Entries
	if err := os.Chmod(p, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
	snap := observe(t, o)
	if _, ok := snap.Unread["tool:kubectl"]; !ok {
		t.Fatalf("unread = %v entries=%v", snap.Unread, snap.Entries)
	}
	if fs := Compare(base, snap, o); len(fs) != 0 {
		t.Errorf("unread tool compared: %+v", fs)
	}
}

// TestUpgradeNoise simulates ordinary upgrades with the layouts they really
// have: Homebrew upgrades git, gh, node (whose npm goes through the Cellar to
// the npm copied into lib/node_modules) and pyenv (whose rehashed shims hold
// its path), and pyenv switches the global Python version. What fires is the
// measurement.
func TestUpgradeNoise(t *testing.T) {
	skipWindows(t)
	home, prefix := t.TempDir(), t.TempDir()
	shims := filepath.Join(home, ".pyenv", "shims")
	o := brewOptions(home, prefix, shims)
	cellar(t, prefix, "2.45.0", "git")
	brewNode(t, prefix, "22.1.0", "npm 10.7")
	cellar(t, prefix, "2.50.0", "gh")
	cellar(t, prefix, "2.4.0", "pyenv")
	pyenvShims(t, shims, filepath.Join(prefix, "Cellar", "pyenv", "2.4.0", "libexec", "pyenv"))
	write(t, filepath.Join(home, ".pyenv", "version"), "3.12.4\n")
	base := observe(t, o).Entries

	// The version switch alone changes no tool file.
	write(t, filepath.Join(home, ".pyenv", "version"), "3.13.0\n")
	if fs := Compare(base, observe(t, o), o); len(fs) != 0 {
		t.Fatalf("pyenv switch fired: %+v", fs)
	}

	cellar(t, prefix, "2.46.0", "git")
	brewNode(t, prefix, "22.2.0", "npm 10.8")
	cellar(t, prefix, "2.51.0_1", "gh")
	cellar(t, prefix, "2.4.1", "pyenv")
	pyenvShims(t, shims, filepath.Join(prefix, "Cellar", "pyenv", "2.4.1", "libexec", "pyenv"))
	fs := Compare(base, observe(t, o), o)
	got := ids(fs)
	t.Logf("brew upgrade of git, gh, node with npm, pyenv with its shims: %v", got)
	if len(fs) != 1 || got["DV-101/medium"] != 1 {
		t.Fatalf("want one grouped medium finding, got %s", evidenceOf(fs))
	}
	for _, n := range []string{"tool:git", "tool:node", "tool:npm", "tool:gh", "tool:pyenv", "tool:python", "tool:python3"} {
		if !strings.Contains(fs[0].Location, n) {
			t.Errorf("grouped finding lacks %s", n)
		}
	}
}

// The baseline holds paths under home as ~/..., never the home folder itself.
func TestToolsHomeShown(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	script(t, filepath.Join(bin, "aws"), "ok")
	obs := observe(t, Options{Home: home, Path: bin, Getenv: envOf(nil)}).Entries["tool:aws"]
	if obs["entry"] != "~/.local/bin/aws" {
		t.Errorf("entry = %q", obs["entry"])
	}
	for _, v := range obs {
		if strings.Contains(v, home) || strings.Contains(v, filepath.ToSlash(home)) {
			t.Errorf("observation names home: %v", obs)
		}
	}
	_ = watch.Observation(obs)
}
