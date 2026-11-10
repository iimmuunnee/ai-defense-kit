package device

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shellCase observes the tools in the baseline PATH and in the shell's PATH
// and returns what the shell lookup adds.
func shellCase(t *testing.T, o Options, base Snapshot, shellPath string) ([]string, string) {
	t.Helper()
	cur := observe(t, o)
	so := o
	so.Path = shellPath
	fs := CompareShell(base.Entries, cur, ObserveTools(so), o)
	var got []string
	for k, n := range ids(fs) {
		for range n {
			got = append(got, k)
		}
	}
	return got, evidenceOf(fs)
}

// A same-name tool in a new folder at the front of the shell's PATH.
func TestShellPathShadow(t *testing.T) {
	skipWindows(t)
	home, bin, evil := t.TempDir(), t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	script(t, filepath.Join(bin, "git"), "ok")
	base := observe(t, o)
	script(t, filepath.Join(evil, "git"), "payload")
	got, ev := shellCase(t, o, base, evil+string(os.PathListSeparator)+bin)
	if len(got) != 1 || got[0] != "DV-101/high" {
		t.Fatalf("findings = %v\n%s", got, ev)
	}
	// Evidence names both lookups.
	if !strings.Contains(ev, "지금 셸의 PATH") || !strings.Contains(ev, "기준값의 PATH") || !strings.Contains(ev, filepath.ToSlash(filepath.Join(evil, "git"))) {
		t.Errorf("evidence = %s", ev)
	}
	// The same file first in the shell's PATH: nothing.
	if got, ev := shellCase(t, o, base, bin+string(os.PathListSeparator)+evil); len(got) != 0 {
		t.Errorf("same file: %v\n%s", got, ev)
	}
}

// A short PATH, as cron gives, finds fewer tools: that alone is nothing.
func TestShellPathShort(t *testing.T) {
	skipWindows(t)
	home, bin, short := t.TempDir(), t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, Getenv: envOf(nil)}
	script(t, filepath.Join(bin, "git"), "ok")
	script(t, filepath.Join(bin, "node"), "ok")
	base := observe(t, o)
	if got, ev := shellCase(t, o, base, short); len(got) != 0 {
		t.Errorf("short PATH: %v\n%s", got, ev)
	}
}

// nvm switched the shell to another version: one grouped medium.
func TestShellPathNvmSwitch(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	root := filepath.Join(home, ".nvm")
	o := Options{Home: home, Path: nvmNode(t, root, "v22.1.0"), Getenv: envOf(nil)}
	base := observe(t, o)
	got, ev := shellCase(t, o, base, nvmNode(t, root, "v22.2.0"))
	if len(got) != 1 || got[0] != "DV-101/medium" {
		t.Fatalf("findings = %v\n%s", got, ev)
	}
}
