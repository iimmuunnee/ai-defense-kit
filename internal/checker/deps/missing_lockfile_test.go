package deps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

const (
	harmlessLock = `{"name":"t","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{` +
		`"":{"name":"t","version":"1.0.0","dependencies":{"harmless":"1.0.0"}},` +
		`"node_modules/harmless":{"version":"1.0.0","resolved":"https://registry.npmjs.org/harmless/-/harmless-1.0.0.tgz"}}}`
	declaresMal = `{"name":"x","version":"1.0.0","dependencies":{"demo-mal":"1.0.0"}}`
)

// scanForWarnings runs the real osv-scanner on a hand-made database.
func scanForWarnings(t *testing.T, root string, untrusted bool) string {
	t.Helper()
	c := New(testFS, Options{OfflineDBPath: offlineDB(t)})
	res, err := c.Run(context.Background(), checker.Target{Root: root, Offline: true, Untrusted: untrusted})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(res.Warnings, "\n")
}

func TestWarnsOfSymlinkedLockfile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "real-lock.json")
	if err := os.WriteFile(target, []byte(lockfileBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "package-lock.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	put(t, root, "tools/package-lock.json", harmlessLock)
	for _, untrusted := range []bool{false, true} {
		got := scanForWarnings(t, root, untrusted)
		if !strings.Contains(got, warnLockfileLink+": package-lock.json") {
			t.Errorf("untrusted=%v: warnings = %q", untrusted, got)
		}
	}
}

func TestWarnsOfPackageJSONWithoutLockfile(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", declaresMal)
	put(t, root, "tools/package-lock.json", harmlessLock)
	for _, untrusted := range []bool{false, true} {
		got := scanForWarnings(t, root, untrusted)
		if !strings.Contains(got, warnNoLockBeside+": package.json") {
			t.Errorf("untrusted=%v: warnings = %q", untrusted, got)
		}
	}
}

// The warning also comes when the scanner found no packages at all.
func TestPackageJSONWarningWithNoPackages(t *testing.T) {
	root := t.TempDir()
	put(t, root, "app/package.json", declaresMal)
	got := scanForWarnings(t, root, false)
	if !strings.Contains(got, warnNoLockfile) || !strings.Contains(got, warnNoLockBeside+": app/package.json") {
		t.Errorf("warnings = %q", got)
	}
}

func TestCleanRepositoryGetsNoLockfileWarning(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", declaresMal)
	put(t, root, "package-lock.json", harmlessLock)
	got := scanForWarnings(t, root, false)
	if strings.Contains(got, warnLockfileLink) || strings.Contains(got, warnNoLockBeside) {
		t.Errorf("warnings = %q", got)
	}
}

func TestPackageJSONLockfileCases(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		warn  string // "" means no warning
	}{
		{"lockfile beside", map[string]string{"package.json": declaresMal, "package-lock.json": harmlessLock}, ""},
		{"lockfile in a parent", map[string]string{"packages/a/package.json": declaresMal, "package-lock.json": harmlessLock}, ""},
		{"shrinkwrap", map[string]string{"package.json": declaresMal, "npm-shrinkwrap.json": harmlessLock}, ""},
		{"yarn", map[string]string{"package.json": declaresMal, "yarn.lock": ""}, ""},
		{"pnpm", map[string]string{"package.json": declaresMal, "pnpm-lock.yaml": ""}, ""},
		{"bun", map[string]string{"package.json": declaresMal, "bun.lock": ""}, ""},
		{"nothing declared", map[string]string{"package.json": `{"name":"x","scripts":{"test":"t"}}`}, ""},
		{"empty dependencies", map[string]string{"package.json": `{"dependencies":{}}`}, ""},
		{"skipped folder", map[string]string{"node_modules/a/package.json": declaresMal, "dist/package.json": declaresMal}, ""},
		{"devDependencies", map[string]string{"package.json": `{"devDependencies":{"a":"1"}}`}, "package.json"},
		{"optionalDependencies", map[string]string{"package.json": `{"optionalDependencies":{"a":"1"}}`}, "package.json"},
		{"lockfile only in a sibling", map[string]string{"a/package.json": declaresMal, "b/package-lock.json": harmlessLock}, "a/package.json"},
		{"folder with a lockfile name", map[string]string{"package.json": declaresMal, "package-lock.json/x": ""}, "package.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range c.files {
				put(t, root, rel, body)
			}
			got := strings.Join(lockfileWarnings(root), "\n")
			if c.warn == "" && got != "" {
				t.Errorf("warnings = %q", got)
			}
			if c.warn != "" && got != warnNoLockBeside+": "+c.warn {
				t.Errorf("warnings = %q, want %q", got, c.warn)
			}
		})
	}
}

// A lockfile above the scan root is not in what was scanned.
func TestLockfileAboveTheRootDoesNotCount(t *testing.T) {
	parent := t.TempDir()
	put(t, parent, "package-lock.json", harmlessLock)
	put(t, parent, "app/package.json", declaresMal)
	got := strings.Join(lockfileWarnings(filepath.Join(parent, "app")), "\n")
	if got != warnNoLockBeside+": package.json" {
		t.Errorf("warnings = %q", got)
	}
}
