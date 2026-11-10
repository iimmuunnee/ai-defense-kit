package deps

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	offlineRecord = `{"schema_version":"1.6.0","id":"MAL-2099-1","modified":"2025-01-01T00:00:00Z","published":"2025-01-01T00:00:00Z",` +
		`"summary":"Malicious code in demo (npm)","affected":[{"package":{"ecosystem":"npm","name":"demo-mal"},"versions":["1.0.0"],` +
		`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	lockfileBody = `{"name":"x","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{` +
		`"":{"name":"x","version":"1.0.0","dependencies":{"demo-mal":"1.0.0"}},` +
		`"node_modules/demo-mal":{"version":"1.0.0","resolved":"https://registry.npmjs.org/demo-mal/-/demo-mal-1.0.0.tgz"}}}`
)

// offlineDB is a hand-made OSV database holding one malicious package.
func offlineDB(t *testing.T) string {
	t.Helper()
	db := t.TempDir()
	dir := filepath.Join(db, "osv-scalibr", "npm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "all.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z := zip.NewWriter(f)
	w, err := z.Create("MAL-2099-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(offlineRecord)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return db
}

func put(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// findsMAL scans with the real osv-scanner and reports whether the package was found.
func findsMAL(t *testing.T, root, db string, untrusted bool) (bool, checker.Result) {
	t.Helper()
	c := New(testFS, Options{OfflineDBPath: db})
	res, err := c.Run(context.Background(), checker.Target{Root: root, Offline: true, Untrusted: untrusted})
	if err != nil {
		t.Fatalf("untrusted=%v: %v", untrusted, err)
	}
	return slices.ContainsFunc(res.Findings, func(f finding.Finding) bool { return strings.Contains(f.ID, "MAL-2099-1") }), res
}

func TestUntrustedScansLockfilesGitignoreHides(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	db := offlineDB(t)
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
	}{
		{"root file, no repository", func(t *testing.T, root string) {
			put(t, root, "package-lock.json", lockfileBody)
			put(t, root, ".gitignore", "package-lock.json\n")
		}},
		{"root file, repository", func(t *testing.T, root string) {
			put(t, root, "package-lock.json", lockfileBody)
			put(t, root, ".gitignore", "package-lock.json\n")
			gitIn(t, root, "init", "-q")
			gitIn(t, root, "add", ".gitignore")
			gitIn(t, root, "commit", "-qm", "a")
		}},
		{"file in a subfolder", func(t *testing.T, root string) {
			put(t, root, "sub/package-lock.json", lockfileBody)
			put(t, root, "sub/.gitignore", "*.json\n")
		}},
		{"ignored folder", func(t *testing.T, root string) {
			put(t, root, "app/package-lock.json", lockfileBody)
			put(t, root, ".gitignore", "app/\n")
		}},
		{"committed lockfile", func(t *testing.T, root string) {
			put(t, root, "package-lock.json", lockfileBody)
			put(t, root, ".gitignore", "package-lock.json\n")
			gitIn(t, root, "init", "-q")
			gitIn(t, root, "add", "-f", ".")
			gitIn(t, root, "commit", "-qm", "a")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.setup(t, root)
			if found, _ := findsMAL(t, root, db, false); found {
				t.Error("control: without --untrusted .gitignore should hide the lockfile")
			}
			found, res := findsMAL(t, root, db, true)
			if !found {
				t.Errorf("--untrusted missed it: %+v", res)
			}
		})
	}
}

// Control: the database and the lockfile work on their own.
func TestOfflineFixtureFindsThePackage(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package-lock.json", lockfileBody)
	db := offlineDB(t)
	if found, res := findsMAL(t, root, db, false); !found {
		t.Errorf("%+v", res)
	}
}

// An osv-scanner.toml is overridden together with .gitignore.
func TestUntrustedOverridesConfigWithTheRealScanner(t *testing.T) {
	root := t.TempDir()
	put(t, root, "sub/package-lock.json", lockfileBody)
	put(t, root, "sub/osv-scanner.toml", "[[IgnoredVulns]]\nid = \"MAL-2099-1\"\nreason = \"x\"\n")
	db := offlineDB(t)
	if found, _ := findsMAL(t, root, db, false); found {
		t.Error("control: the config should hide it")
	}
	if found, res := findsMAL(t, root, db, true); !found {
		t.Errorf("%+v", res)
	}
}

func TestDepsOverrideInsideTheRootFails(t *testing.T) {
	root := t.TempDir()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, root)
	}
	scanned := false
	c := New(testFS, Options{Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
		scanned = true
		return models.VulnerabilityResults{}, nil
	}})
	_, err := c.Run(context.Background(), checker.Target{Root: root, Untrusted: true})
	if err == nil || !strings.Contains(err.Error(), "--untrusted") {
		t.Fatalf("err = %v", err)
	}
	if scanned {
		t.Error("scanned with a file inside the repository")
	}
	if strings.Contains(err.Error(), root) {
		t.Errorf("error holds the path: %v", err)
	}
	if ents, err := os.ReadDir(root); err != nil || len(ents) != 0 {
		t.Errorf("left behind: %v %v", ents, err)
	}
}
