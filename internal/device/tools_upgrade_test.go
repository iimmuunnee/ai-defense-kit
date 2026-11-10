package device

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// brewNode lays out Homebrew's node at version v the way its post-install
// step does: bin/node -> ../Cellar/node/<v>/bin/node, and npm through the
// Cellar's own bin/npm to the npm copied into <prefix>/lib/node_modules. Both
// npm links are absolute. npmWord is what npm-cli.js says.
func brewNode(t *testing.T, prefix, v, npmWord string) {
	t.Helper()
	cellar(t, prefix, v, "node")
	cli := filepath.Join(prefix, "lib", "node_modules", "npm", "bin", "npm-cli.js")
	script(t, cli, npmWord)
	relink(t, cli, filepath.Join(prefix, "Cellar", "node", v, "bin", "npm"))
	relink(t, filepath.Join(prefix, "Cellar", "node", v, "bin", "npm"), filepath.Join(prefix, "bin", "npm"))
}

func brewOptions(home, prefix string, extra ...string) Options {
	return Options{
		Home:   home,
		Path:   strings.Join(append(extra, filepath.Join(prefix, "bin")), string(os.PathListSeparator)),
		Getenv: envOf(map[string]string{"HOMEBREW_PREFIX": prefix}),
	}
}

func evidenceOf(fs []finding.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Location + " " + f.Evidence + "\n")
	}
	return b.String()
}

// brew upgrade node: only the middle hop of npm's links moves to the new
// version folder, and npm itself is rewritten in place under lib/node_modules.
func TestUpgradeBrewNpmMiddleHop(t *testing.T) {
	skipWindows(t)
	home, prefix := t.TempDir(), t.TempDir()
	o := brewOptions(home, prefix)
	brewNode(t, prefix, "22.1.0", "npm 10.7")
	base := observe(t, o).Entries
	brewNode(t, prefix, "22.2.0", "npm 10.8")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 || !strings.Contains(fs[0].Location, "tool:npm") || !strings.Contains(fs[0].Location, "tool:node") {
		t.Fatalf("findings = %s", evidenceOf(fs))
	}
	if !strings.Contains(fs[0].Evidence, "22.2.0") {
		t.Errorf("evidence = %s", fs[0].Evidence)
	}
}

// The same middle-hop move, but npm's file is not where Homebrew rewrites it
// in place: its content change is not an upgrade.
func TestUpgradeMiddleHopElsewhere(t *testing.T) {
	skipWindows(t)
	home, prefix := t.TempDir(), t.TempDir()
	o := brewOptions(home, prefix)
	cli := filepath.Join(prefix, "share", "npm-cli.js")
	lay := func(v, word string) {
		script(t, cli, word)
		relink(t, cli, filepath.Join(prefix, "Cellar", "node", v, "bin", "npm"))
		relink(t, filepath.Join(prefix, "Cellar", "node", v, "bin", "npm"), filepath.Join(prefix, "bin", "npm"))
	}
	lay("22.1.0", "a")
	base := observe(t, o).Entries
	lay("22.2.0", "b")
	fs := Compare(base, observe(t, o), o)
	// share/ is not Homebrew's own folder, so this is DV-102 in place of DV-101.
	if len(fs) != 1 || ids(fs)["DV-102/high"] != 1 {
		t.Fatalf("findings = %s", evidenceOf(fs))
	}
	// The hop that moved is named, not "target -> same target".
	if !strings.Contains(fs[0].Evidence, "링크 단계") || !strings.Contains(fs[0].Evidence, "22.2.0") {
		t.Errorf("evidence = %s", fs[0].Evidence)
	}
}

// npm linked through relative links into the Cellar's own copy.
func TestUpgradeBrewNpmInCellar(t *testing.T) {
	skipWindows(t)
	home, prefix := t.TempDir(), t.TempDir()
	o := brewOptions(home, prefix)
	lay := func(v string) {
		cellar(t, prefix, v, "node")
		script(t, filepath.Join(prefix, "Cellar", "node", v, "lib", "node_modules", "npm", "bin", "npm-cli.js"), "npm "+v)
		relink(t, filepath.Join("..", "lib", "node_modules", "npm", "bin", "npm-cli.js"), filepath.Join(prefix, "Cellar", "node", v, "bin", "npm"))
		relink(t, filepath.Join("..", "Cellar", "node", v, "bin", "npm"), filepath.Join(prefix, "bin", "npm"))
	}
	lay("22.1.0")
	base := observe(t, o).Entries
	lay("22.2.0")
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 {
		t.Fatalf("findings = %s", evidenceOf(fs))
	}
}

// pyenvShims writes shims that hold the path of the pyenv they call, as
// `pyenv rehash` does.
func pyenvShims(t *testing.T, shims, pyenv string) {
	t.Helper()
	for _, n := range []string{"python", "python3"} {
		if err := os.MkdirAll(shims, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(shims, n), []byte("#!/bin/sh\nexec \""+pyenv+"\" exec \"$0\" \"$@\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// brew upgrade pyenv, then rehash: the shims change with it.
func TestUpgradePyenvShims(t *testing.T) {
	skipWindows(t)
	for _, custom := range []bool{false, true} {
		home, prefix := t.TempDir(), t.TempDir()
		root := filepath.Join(home, ".pyenv")
		o := brewOptions(home, prefix)
		if custom {
			root = filepath.Join(t.TempDir(), "pyroot")
			o.Getenv = envOf(map[string]string{"HOMEBREW_PREFIX": prefix, "PYENV_ROOT": root})
		}
		shims := filepath.Join(root, "shims")
		o.Path = shims + string(os.PathListSeparator) + o.Path
		cellar(t, prefix, "2.4.0", "pyenv")
		pyenvShims(t, shims, filepath.Join(prefix, "Cellar", "pyenv", "2.4.0", "libexec", "pyenv"))
		base := observe(t, o).Entries

		// The shims alone changed: not an upgrade.
		pyenvShims(t, shims, filepath.Join(prefix, "elsewhere", "pyenv"))
		if fs := Compare(base, observe(t, o), o); len(fs) != 2 || ids(fs)["DV-101/high"] != 2 {
			t.Errorf("custom=%v shims alone: %s", custom, evidenceOf(fs))
		}

		cellar(t, prefix, "2.4.1", "pyenv")
		pyenvShims(t, shims, filepath.Join(prefix, "Cellar", "pyenv", "2.4.1", "libexec", "pyenv"))
		fs := Compare(base, observe(t, o), o)
		if len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 {
			t.Fatalf("custom=%v upgrade: %s", custom, evidenceOf(fs))
		}
		for _, k := range []string{"tool:pyenv", "tool:python", "tool:python3"} {
			if !strings.Contains(fs[0].Location, k) {
				t.Errorf("custom=%v: grouped finding lacks %s: %s", custom, k, fs[0].Location)
			}
		}
	}
}

// nvmNode lays out nvm's node at version v and returns its bin folder.
func nvmNode(t *testing.T, root, v string) string {
	t.Helper()
	bin := filepath.Join(root, "versions", "node", v, "bin")
	script(t, filepath.Join(bin, "node"), "node "+v)
	cli := filepath.Join(root, "versions", "node", v, "lib", "node_modules", "npm", "bin", "npm-cli.js")
	script(t, cli, "npm "+v)
	relink(t, filepath.Join("..", "lib", "node_modules", "npm", "bin", "npm-cli.js"), filepath.Join(bin, "npm"))
	return bin
}

// nvm use / nvm alias default: the PATH folder moves to another version.
func TestUpgradeNvm(t *testing.T) {
	skipWindows(t)
	for _, custom := range []bool{false, true} {
		home := t.TempDir()
		root := filepath.Join(home, ".nvm")
		env := map[string]string{}
		if custom {
			root = filepath.Join(t.TempDir(), "nvm")
			env["NVM_DIR"] = root
		}
		o := Options{Home: home, Path: nvmNode(t, root, "v22.1.0"), Getenv: envOf(env)}
		base := observe(t, o).Entries
		o.Path = nvmNode(t, root, "v22.2.0")
		fs := Compare(base, observe(t, o), o)
		if len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 || !strings.Contains(fs[0].Location, "tool:node") || !strings.Contains(fs[0].Location, "tool:npm") {
			t.Fatalf("custom=%v: %s", custom, evidenceOf(fs))
		}
		o.Path = nvmNode(t, root, "v22.2.0-evil")
		if fs := Compare(base, observe(t, o), o); len(fs) != 2 || ids(fs)["DV-101/high"] != 2 {
			t.Errorf("custom=%v non-version folder: %s", custom, evidenceOf(fs))
		}
	}
}

// fnmShell makes the per-shell folder fnm puts on PATH: a link to one
// installed version. It returns its bin folder.
func fnmShell(t *testing.T, home, id, v string) string {
	t.Helper()
	inst := filepath.Join(home, ".local", "share", "fnm", "node-versions", v, "installation")
	if _, err := os.Stat(filepath.Join(inst, "bin", "node")); err != nil {
		script(t, filepath.Join(inst, "bin", "node"), "node "+v)
	}
	shell := filepath.Join(home, ".local", "state", "fnm_multishells", id)
	relink(t, inst, shell)
	return filepath.Join(shell, "bin")
}

func TestFnmMultishell(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	o := Options{Home: home, Path: fnmShell(t, home, "1111_2222", "v22.1.0"), Getenv: envOf(nil)}
	base := observe(t, o).Entries
	// The same node in a new shell: nothing changed.
	o.Path = fnmShell(t, home, "3333_4444", "v22.1.0")
	if fs := Compare(base, observe(t, o), o); len(fs) != 0 {
		t.Errorf("new shell: %s", evidenceOf(fs))
	}
	// Another version: an upgrade.
	o.Path = fnmShell(t, home, "5555_6666", "v22.2.0")
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/medium"] != 1 {
		t.Errorf("new version: %s", evidenceOf(fs))
	}
	// A shell folder that leads somewhere else: not an upgrade.
	other := t.TempDir()
	script(t, filepath.Join(other, "bin", "node"), "payload")
	shell := filepath.Join(home, ".local", "state", "fnm_multishells", "7777_8888")
	relink(t, other, shell)
	o.Path = filepath.Join(shell, "bin")
	if fs := Compare(base, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-101/high"] != 1 {
		t.Errorf("elsewhere: %s", evidenceOf(fs))
	}
}

// A DV-102 change lists what changed, so a content change does not read
// like a new target.
func TestOutsideChangeParts(t *testing.T) {
	skipWindows(t)
	home, prefix, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755); err != nil {
		t.Fatal(err)
	}
	o := brewOptions(home, prefix)
	script(t, filepath.Join(elsewhere, "gh"), "ok")
	relink(t, filepath.Join(elsewhere, "gh"), filepath.Join(prefix, "bin", "gh"))
	base := observe(t, o).Entries
	script(t, filepath.Join(elsewhere, "gh"), "changed")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || ids(fs)["DV-102/high"] != 1 || !strings.Contains(fs[0].Evidence, "내용(SHA-256)이 다름") || strings.Contains(fs[0].Evidence, "링크 대상") {
		t.Fatalf("findings = %s", evidenceOf(fs))
	}
}
