package deps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/kev"
)

func TestDepsUntrustedPassesOverride(t *testing.T) {
	root := t.TempDir()
	var path string
	var sizeDuringScan int64 = -1
	scan := func(a osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
		path = a.ConfigOverridePath
		if st, err := os.Stat(path); err == nil {
			sizeDuringScan = st.Size()
		}
		return loadResults(t, root), nil
	}
	c := New(testFS, Options{Scan: scan, FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil }})
	if _, err := c.Run(context.Background(), checker.Target{Root: root, Untrusted: true}); err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Fatal("no override given")
	}
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		t.Errorf("override %s is inside the repository", path)
	}
	if sizeDuringScan != 0 {
		t.Errorf("override size during the scan = %d", sizeDuringScan)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("override not removed: %v", err)
	}

	path = "unset"
	if _, err := c.Run(context.Background(), checker.Target{Root: root}); err != nil {
		t.Fatal(err)
	}
	if path != "" {
		t.Errorf("override without --untrusted: %q", path)
	}
}

func TestDepsUntrustedRemovesOverrideWhenTheScanFails(t *testing.T) {
	var path string
	c := New(testFS, Options{Scan: func(a osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
		path = a.ConfigOverridePath
		return models.VulnerabilityResults{}, errors.New("boom")
	}})
	if _, err := c.Run(context.Background(), checker.Target{Root: t.TempDir(), Untrusted: true}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("override not removed: %v", err)
	}
}

func TestDepsUntrustedOverrideFailure(t *testing.T) {
	root := t.TempDir()
	scanned := false
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			scanned = true
			return models.VulnerabilityResults{}, nil
		},
		NewOverride: func() (string, error) {
			return "", &os.PathError{Op: "open", Path: filepath.Join(root, "secret-place"), Err: errors.New("no space")}
		},
	})
	checks := func() checker.CheckStatus {
		_, st := checker.RunAll(context.Background(), []checker.Checker{c}, checker.Target{Root: root, Untrusted: true}, 0)
		return st[0]
	}()
	if checks.Status != checker.StatusFailed {
		t.Fatalf("status = %s", checks.Status)
	}
	if scanned {
		t.Error("scanned without the override")
	}
	if !strings.Contains(checks.Error, "--untrusted") || !strings.Contains(checks.Error, "no space") || strings.Contains(checks.Error, "secret-place") {
		t.Errorf("error = %q", checks.Error)
	}
	if len(checks.External) == 0 || checks.External[0].Status != checker.ExternalSkipped {
		t.Errorf("external = %+v", checks.External)
	}
}

// Real osv-scanner: an empty override file is accepted, one that is gone is an
// error, and its path stays out of the message, which reaches the evidence file.
func TestDepsUntrustedWithTheRealScanner(t *testing.T) {
	root := t.TempDir()
	target := checker.Target{Root: root, Offline: true, Untrusted: true}
	res, err := New(testFS, Options{OfflineDBPath: t.TempDir()}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("empty override: %v", err)
	}
	if len(res.Warnings) == 0 || res.Warnings[0] != warnNoLockfile {
		t.Errorf("warnings = %v", res.Warnings)
	}

	gone := filepath.Join(t.TempDir(), "gone.toml")
	c := New(testFS, Options{OfflineDBPath: t.TempDir(), NewOverride: func() (string, error) { return gone, nil }})
	_, err = c.Run(context.Background(), target)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), filepath.Dir(gone)) || strings.Contains(err.Error(), "gone.toml") {
		t.Errorf("error holds the path: %v", err)
	}
}

func TestDefaultOverrideIsEmpty(t *testing.T) {
	p, err := newEmptyOverride()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	st, err := os.Stat(p)
	if err != nil || st.Size() != 0 {
		t.Errorf("%v %v", st, err)
	}
}
