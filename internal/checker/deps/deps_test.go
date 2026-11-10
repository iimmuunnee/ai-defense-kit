package deps

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/kev"
)

func loadResults(t *testing.T, root string) models.VulnerabilityResults {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/osv/results.json")
	if err != nil {
		t.Fatal(err)
	}
	var r models.VulnerabilityResults
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	// the scanner reports absolute lockfile paths
	for i := range r.Results {
		r.Results[i].Source.Path = filepath.Join(root, r.Results[i].Source.Path)
	}
	return r
}

func loadKEV(t *testing.T) *kev.Catalog {
	t.Helper()
	f, err := os.Open("../../../testdata/kev/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := kev.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var testFS = fstest.MapFS{
	"explain/kinds/vuln-lib.md": {Data: []byte("취약한 라이브러리 설명")},
	"explain/kinds/kev-lib.md":  {Data: []byte("실제 공격 중 설명")},
}

func newChecker(t *testing.T, root string, scanErr error, actions *osvscanner.ScannerActions) checker.Checker {
	return New(testFS, Options{
		Scan: func(a osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			if actions != nil {
				*actions = a
			}
			return loadResults(t, root), scanErr
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
}

func byID(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestDepsKEVIsCriticalExploited(t *testing.T) {
	root := t.TempDir()
	res, err := newChecker(t, root, nil, nil).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(res.Findings))
	}
	f := byID(res.Findings, "GHSA-jfh8-c2jp-5v3q")
	if f == nil || f.Severity != finding.Critical || !f.Exploited {
		t.Fatalf("KEV finding wrong: %+v", f)
	}
	if f.Kind != "kev-lib" {
		t.Errorf("KEV Kind = %q", f.Kind)
	}
	if f.Source != "deps" || f.Confidence != finding.Certain || f.Location != "package-lock.json" {
		t.Errorf("metadata wrong: %+v", f)
	}
	if f.ExplainKo != "실제 공격 중 설명" || !strings.Contains(f.Evidence, "KEV: 실제 공격 중") || !strings.HasPrefix(f.Evidence, "log4js-demo@2.14.1") {
		t.Errorf("explain/evidence wrong: %q / %q", f.ExplainKo, f.Evidence)
	}
	if f.Title != "log4js-demo@2.14.1: Remote code execution via lookup" {
		t.Errorf("title: %q", f.Title)
	}
	if f.Fix != "2.15.0 이상으로 올리세요" {
		t.Errorf("fix: %q", f.Fix)
	}
	want := finding.MakeFingerprint(f.ID, "package-lock.json", "log4js-demo@2.14.1")
	if f.Fingerprint != want {
		t.Errorf("fingerprint %q want %q", f.Fingerprint, want)
	}
	refs := strings.Join(f.References, " ")
	if !strings.Contains(refs, "CVE-2021-44228") || !strings.Contains(refs, "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q") {
		t.Errorf("refs: %v", f.References)
	}

	l := byID(res.Findings, "GHSA-35jh-r3h4-6jhm")
	if l == nil || l.Severity != finding.Critical || l.Exploited || !strings.Contains(l.Evidence, "CVSS 9.8") || l.ExplainKo != "취약한 라이브러리 설명" {
		t.Errorf("cvss finding wrong: %+v", l)
	}
	if l.Kind != "vuln-lib" {
		t.Errorf("Kind = %q", l.Kind)
	}
	n := byID(res.Findings, "GHSA-xxxx-yyyy-zzzz")
	if n == nil || n.Severity != finding.Medium || !strings.Contains(n.Evidence, "점수 없음") {
		t.Errorf("no-score finding wrong: %+v", n)
	}
	if n.Fix != "아직 고친 버전이 없습니다. 원문 링크를 확인하세요." {
		t.Errorf("no-fix text: %q", n.Fix)
	}
}

func vulnWith(vectors ...string) *osvschema.Vulnerability {
	v := &osvschema.Vulnerability{Id: "X"}
	for _, s := range vectors {
		v.Severity = append(v.Severity, &osvschema.Severity{Score: s})
	}
	return v
}

func TestDepsCVSSBuckets(t *testing.T) {
	cases := []struct {
		name string
		v    *osvschema.Vulnerability
		sev  finding.Severity
		memo string
	}{
		{"v3.1 critical", vulnWith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), finding.Critical, "CVSS 9.8"},
		{"v3.0 medium", vulnWith("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), finding.Medium, "CVSS 6.5"},
		{"v3.0 high", vulnWith("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), finding.High, "CVSS 7.5"},
		{"v2 medium", vulnWith("AV:N/AC:L/Au:N/C:P/I:N/A:N"), finding.Medium, "CVSS 5.0"},
		{"v4", vulnWith("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), finding.Critical, "CVSS 9.3"},
		{"max of several", vulnWith("AV:N/AC:L/Au:N/C:P/I:N/A:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), finding.Critical, "CVSS 9.8"},
		{"none", vulnWith(), finding.Medium, "점수 없음"},
		{"garbage", vulnWith("not a vector"), finding.Medium, "점수 없음"},
	}
	for _, c := range cases {
		sev, memo := severityOf(c.v)
		if sev != c.sev || memo != c.memo {
			t.Errorf("%s: got %v %q, want %v %q", c.name, sev, memo, c.sev, c.memo)
		}
	}
}

func TestDepsLowBucket(t *testing.T) {
	sev, _ := severityOf(vulnWith("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"))
	if sev != finding.Low {
		t.Errorf("got %v want Low", sev)
	}
}

func TestDepsVulnsFoundIsNotError(t *testing.T) {
	root := t.TempDir()
	res, err := newChecker(t, root, osvscanner.ErrVulnerabilitiesFound, nil).Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) != 3 {
		t.Fatalf("err=%v findings=%d", err, len(res.Findings))
	}
}

func TestDepsNoPackages(t *testing.T) {
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			return models.VulnerabilityResults{}, osvscanner.ErrNoPackagesFound
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: t.TempDir()})
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("err=%v findings=%d", err, len(res.Findings))
	}
	// "no lockfile" must not look like "no vulnerable dependencies"
	if len(res.Warnings) != 1 || res.Warnings[0] != "의존성 잠금 파일을 찾지 못해 라이브러리 점검을 하지 못했습니다." {
		t.Errorf("Warnings = %v", res.Warnings)
	}
}

func TestDepsNoPackagesWithLoggedErrorFails(t *testing.T) {
	var h slog.Handler
	orig := setLogger
	setLogger = func(x slog.Handler) { h = x }
	defer func() { setLogger = orig }()
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			slog.New(h).Error("failed to extract package-lock.json: bad json")
			return models.VulnerabilityResults{}, osvscanner.ErrNoPackagesFound
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	_, err := c.Run(context.Background(), checker.Target{Root: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "failed to extract package-lock.json") {
		t.Fatalf("want extraction failure, got %v", err)
	}
}

func TestDepsKEVFetchFailWarns(t *testing.T) {
	root := t.TempDir()
	c := New(testFS, Options{
		Scan:     func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) { return loadResults(t, root), nil },
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return nil, errors.New("blocked") },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "KEV 목록을 받지 못해") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("findings should still appear: %d", len(res.Findings))
	}
	if f := byID(res.Findings, "GHSA-jfh8-c2jp-5v3q"); f.Exploited || f.Severity != finding.Medium {
		t.Errorf("without KEV, no exploited flag: %+v", f)
	}
}

func TestDepsScanErrorFails(t *testing.T) {
	root := t.TempDir()
	_, err := newChecker(t, root, osvscanner.ErrAPIFailed, nil).Run(context.Background(), checker.Target{Root: root})
	if err == nil || errors.Is(err, checker.ErrSkipped) {
		t.Fatalf("want failure, got %v", err)
	}
}

func TestDepsOfflineWithoutDBSkips(t *testing.T) {
	root := t.TempDir()
	_, err := newChecker(t, root, nil, nil).Run(context.Background(), checker.Target{Root: root, Offline: true})
	if !errors.Is(err, checker.ErrSkipped) {
		t.Fatalf("want ErrSkipped, got %v", err)
	}
}

func TestDepsOfflineUsesDBAndSkipsKEV(t *testing.T) {
	root := t.TempDir()
	var got osvscanner.ScannerActions
	kevCalled := false
	c := New(testFS, Options{
		OfflineDBPath: "/db",
		Scan: func(a osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			got = a
			return loadResults(t, root), nil
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { kevCalled = true; return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if !got.CompareOffline || got.LocalDBPath != "/db" || kevCalled {
		t.Errorf("offline actions wrong: %+v kev=%v", got, kevCalled)
	}
	if len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "오프라인") || res.Warnings[1] != warnMalOffline {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDepsActionsHaveTransitiveDisabled(t *testing.T) {
	root := t.TempDir()
	var got osvscanner.ScannerActions
	if _, err := newChecker(t, root, nil, &got).Run(context.Background(), checker.Target{Root: root}); err != nil {
		t.Fatal(err)
	}
	if !got.TransitiveScanning.Disabled || !got.Recursive || len(got.DirectoryPaths) != 1 || got.CompareOffline {
		t.Errorf("actions: %+v", got)
	}
	// the vendored-code extractor sends file paths and hashes to api.osv.dev
	if !slices.Contains(got.PluginsDisabled, "filesystem/vendored") {
		t.Errorf("PluginsDisabled = %v, want filesystem/vendored", got.PluginsDisabled)
	}
}

func TestDepsDedupSameLockfileSamePackage(t *testing.T) {
	root := t.TempDir()
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			r := loadResults(t, root)
			r.Results = append(r.Results, r.Results[0]) // same lockfile reported twice
			return r, nil
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) != 3 {
		t.Fatalf("err=%v findings=%d", err, len(res.Findings))
	}
}

func TestDepsSkipsLicenseOnlyEntries(t *testing.T) {
	root := t.TempDir()
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			r := loadResults(t, root)
			r.Results[0].Packages[0].LicenseViolations = []models.License{"GPL-3.0"}
			return r, nil
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) != 3 {
		t.Fatalf("err=%v findings=%d", err, len(res.Findings))
	}
}

func fixVuln(pkg, eco string, fixes ...string) *osvschema.Vulnerability {
	v := &osvschema.Vulnerability{Id: "X"}
	var rs []*osvschema.Range
	for _, f := range fixes {
		rs = append(rs, &osvschema.Range{Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: f}}})
	}
	v.Affected = []*osvschema.Affected{{Package: &osvschema.Package{Name: pkg, Ecosystem: eco}, Ranges: rs}}
	return v
}

func TestFixForMultiRange(t *testing.T) {
	v := fixVuln("lib", "npm", "1.9.2", "2.3.0")
	cases := []struct{ ver, want string }{
		{"2.1.0", "2.3.0 이상으로 올리세요"},
		{"1.5.0", "1.9.2 이상으로 올리세요"},
		{"2.3.0", fixMulti},
		{"weird", fixMulti},
	}
	for _, c := range cases {
		got := fixFor(v, models.PackageInfo{Name: "lib", Version: c.ver, Ecosystem: "npm"})
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.ver, got, c.want)
		}
	}
	if got := fixFor(v, models.PackageInfo{Name: "lib", Version: "2.1.0", Ecosystem: "PyPI"}); got != fixNone {
		t.Errorf("other ecosystem should not match: %q", got)
	}
}

func TestTitleAndRefsFallbacks(t *testing.T) {
	if got := titleText(&osvschema.Vulnerability{Id: "GHSA-1"}); got != "GHSA-1" {
		t.Errorf("title: %q", got)
	}
	got := cveIDs(&osvschema.Vulnerability{Id: "CVE-2024-1", Aliases: []string{"CVE-2024-1", "GHSA-x"}})
	if len(got) != 1 {
		t.Errorf("cves: %v", got)
	}
}

func TestFlattenPanicBecomesError(t *testing.T) {
	r := loadResults(t, t.TempDir())
	r.Results[0].Packages[0].Groups = nil // Flatten panics without group info
	if _, err := flatten(r); err == nil {
		t.Error("expected error")
	}
}

func TestDepsLoggedErrorFails(t *testing.T) {
	root := t.TempDir()
	var h slog.Handler
	orig := setLogger
	setLogger = func(x slog.Handler) { h = x }
	defer func() { setLogger = orig }()
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			l := slog.New(h)
			l.Info("scanning")
			l.Error("max retries exceeded: Forbidden")
			return loadResults(t, root), nil // osv-scanner returns nil despite the failure
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	_, err := c.Run(context.Background(), checker.Target{Root: root})
	if err == nil || errors.Is(err, checker.ErrSkipped) || !strings.Contains(err.Error(), "OSV 취약점 DB 조회에 실패했습니다: max retries exceeded") {
		t.Fatalf("want lookup failure, got %v", err)
	}
}

func TestDepsInfoLogsAreNotErrors(t *testing.T) {
	root := t.TempDir()
	var h slog.Handler
	orig := setLogger
	setLogger = func(x slog.Handler) { h = x }
	defer func() { setLogger = orig }()
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			slog.New(h).Warn("just a warning")
			return loadResults(t, root), nil
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	if _, err := c.Run(context.Background(), checker.Target{Root: root}); err != nil {
		t.Fatal(err)
	}
}

// requirementsResult builds a scan result for root/requirements.txt with
// one finding per package, reusing the shape of the fixture. A package is
// "name" (fixture version) or "name@version".
func requirementsResult(t *testing.T, root string, pkgs ...string) models.VulnerabilityResults {
	t.Helper()
	return reqResultAt(t, root, "requirements.txt", pkgs...)
}

// reqResultAt is requirementsResult for root/rel.
func reqResultAt(t *testing.T, root, rel string, pkgs ...string) models.VulnerabilityResults {
	t.Helper()
	base := loadResults(t, root)
	src := base.Results[0]
	res := models.PackageSource{Source: models.SourceInfo{Path: filepath.Join(root, rel), Type: "lockfile"}}
	for _, n := range pkgs {
		p := src.Packages[0]
		name, ver, ok := strings.Cut(n, "@")
		p.Package.Name = name
		if ok {
			p.Package.Version = ver
		}
		p.Package.Ecosystem = "PyPI"
		res.Packages = append(res.Packages, p)
	}
	base.Results = append(base.Results, res)
	return base
}

// warnWith returns the warning containing sub, or "".
func warnWith(ws []string, sub string) string {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return w
		}
	}
	return ""
}

const (
	subUnpinned    = "정확히 고정하지 않은"
	subUnconfirmed = "고정 여부를 확인할 수 없는"
)

func runWithResults(t *testing.T, root string, r models.VulnerabilityResults) checker.Result {
	t.Helper()
	c := New(testFS, Options{
		Scan:     func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) { return r, nil },
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func countAt(fs []finding.Finding, loc string) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		if f.Location == loc {
			m[strings.SplitN(f.Evidence, "@", 2)[0]]++
		}
	}
	return m
}

func TestDepsDropsNonExactRequirementFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("numpy>=1.2\nDjango==4.2.1\nPytest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runWithResults(t, root, requirementsResult(t, root, "numpy", "django@4.2.1"))
	got := countAt(res.Findings, "requirements.txt")
	if got["django"] == 0 || got["numpy"] != 0 {
		t.Errorf("requirements findings: %v", got)
	}
	if len(res.Findings) != 3+got["django"] {
		t.Errorf("lockfile findings must stay: %d", len(res.Findings))
	}
	var warn string
	for _, w := range res.Warnings {
		if strings.Contains(w, "정확히 고정하지 않은") {
			warn = w
		}
	}
	if !strings.Contains(warn, "numpy, pytest") || strings.Contains(warn, "django") || !strings.Contains(warn, `("==" 로 고정하면 점검할 수 있습니다)`) {
		t.Errorf("warning: %q", warn)
	}
}

func TestDepsKeepsLockfileFindings(t *testing.T) {
	root := t.TempDir()
	res := runWithResults(t, root, loadResults(t, root))
	if len(res.Findings) != 3 || len(res.Warnings) != 0 {
		t.Errorf("findings=%d warnings=%v", len(res.Findings), res.Warnings)
	}
}

func TestDepsRequirementsUnreadableDropsAndNames(t *testing.T) {
	root := t.TempDir() // requirements.txt does not exist
	res := runWithResults(t, root, requirementsResult(t, root, "numpy"))
	if n := countAt(res.Findings, "requirements.txt")["numpy"]; n != 0 {
		t.Error("unconfirmable findings must be dropped")
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "requirements.txt 파일을 읽지 못해") ||
		!strings.Contains(joined, "고정 여부를 확인할 수 없는 라이브러리는 결과에서 뺐습니다: numpy (직접 확인해 주세요)") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDepsRequirementsEmptyVersionDropped(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("django==4.2.1\n"), 0o644)
	r := requirementsResult(t, root, "django")
	r.Results[len(r.Results)-1].Packages[0].Package.Version = ""
	res := runWithResults(t, root, r)
	if countAt(res.Findings, "requirements.txt")["django"] != 0 {
		t.Error("empty version must be dropped")
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "뺐습니다: django") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDepsRequirementsPackageNotListedDropped(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("django==4.2.1\n"), 0o644)
	res := runWithResults(t, root, requirementsResult(t, root, "django@4.2.1", "ghost"))
	got := countAt(res.Findings, "requirements.txt")
	if got["django"] == 0 || got["ghost"] != 0 {
		t.Errorf("got %v", got)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "뺐습니다: ghost (직접") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDepsNoPackagesStillWarnsUnpinned(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("numpy>=1\n"), 0o644)
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			return models.VulnerabilityResults{}, osvscanner.ErrNoPackagesFound
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Warnings) != 2 || res.Warnings[0] != warnNoLockfile || !strings.Contains(res.Warnings[1], "numpy") {
		t.Fatalf("err=%v warnings=%v", err, res.Warnings)
	}
}

func TestDepsFollowsDashR(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("-r base.txt\n"), 0o644)
	os.WriteFile(filepath.Join(root, "base.txt"), []byte("numpy>=1\ndjango==4.2.1\n"), 0o644)
	res := runWithResults(t, root, requirementsResult(t, root, "numpy", "django@4.2.1"))
	got := countAt(res.Findings, "requirements.txt")
	if got["django"] == 0 || got["numpy"] != 0 {
		t.Errorf("got %v", got)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "numpy") {
		t.Errorf("included file's unpinned names must be warned: %v", res.Warnings)
	}
}

func TestLoadRequirementsTreeLimits(t *testing.T) {
	root := t.TempDir()
	w := func(name, s string) { os.WriteFile(filepath.Join(root, name), []byte(s), 0o644) }
	w("requirements.txt", "-r a.txt\n")
	w("a.txt", "-r requirements.txt\nfoo==1\n-r ../outside.txt\n") // cycle + escape
	reqs, bad := loadRequirementsTree(root, filepath.Join(root, "requirements.txt"))
	if len(reqs) != 1 || len(bad) != 1 {
		t.Errorf("reqs=%v bad=%v", reqs, bad)
	}
	// depth: chain of 7 files
	for i := 0; i < 7; i++ {
		w("c"+string(rune('0'+i))+".txt", "-r c"+string(rune('1'+i))+".txt\n")
	}
	_, bad = loadRequirementsTree(root, filepath.Join(root, "c0.txt"))
	if len(bad) != 1 {
		t.Errorf("depth limit should report one unreadable include: %v", bad)
	}
}

func TestDepsSymlinkedRequirementsDroppedAndRootResolved(t *testing.T) {
	real := t.TempDir()
	os.WriteFile(filepath.Join(real, "elsewhere.txt"), []byte("django==4.2.1\n"), 0o644)
	if err := os.Symlink(filepath.Join(real, "elsewhere.txt"), filepath.Join(real, "requirements.txt")); err != nil {
		t.Skip("symlinks unavailable")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	// scanner reports the unresolved absolute path; root given via symlink
	res := runWithResults(t, link, requirementsResult(t, link, "django"))
	if len(res.Findings) != 3 {
		t.Errorf("symlinked requirements file must not be trusted: %d", len(res.Findings))
	}
	// lockfile findings keep a clean relative location through the symlinked root
	if f := byID(res.Findings, "GHSA-jfh8-c2jp-5v3q"); f == nil || f.Location != "package-lock.json" {
		t.Errorf("location: %+v", f)
	}
}

func TestDepsWarnsFromAllRequirementsFilesAndSkipsExcluded(t *testing.T) {
	root := t.TempDir()
	w := func(rel, s string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("requirements-dev.txt", "flask~=2.0\n")
	w("sub/requirements.txt", "flask>=1\nb==1\n")
	w("node_modules/x/requirements.txt", "hidden\n")
	w(".venv/requirements.txt", "hidden2\n")
	var many string
	for i := 0; i < 12; i++ {
		many += string(rune('a'+i)) + "lib\n"
	}
	w("requirements-many.txt", many)
	res := runWithResults(t, root, loadResults(t, root))
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	x := res.Warnings[0]
	if strings.Contains(x, "hidden") || strings.Count(x, "flask") != 1 || !strings.Contains(x, "외 3개") || strings.Contains(x, ": b,") || strings.Contains(x, ", b,") {
		t.Errorf("warning: %q", x)
	}
}

func TestDepsDashPrefixedRequirementsFileFiltered(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "dev-requirements.txt"), []byte("numpy>=1.2\n"), 0o644)
	res := runWithResults(t, root, reqResultAt(t, root, "dev-requirements.txt", "numpy@1.2"))
	if n := countAt(res.Findings, "dev-requirements.txt")["numpy"]; n != 0 {
		t.Errorf("dev-requirements.txt finding must be dropped: %v", res.Findings)
	}
	if w := warnWith(res.Warnings, subUnpinned); !strings.Contains(w, "numpy") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	if warnWith(res.Warnings, subUnconfirmed) != "" {
		t.Errorf("no double naming: %v", res.Warnings)
	}
}

func TestDepsKeepsOnlyPinnedVersionWithMarkers(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"),
		[]byte("numpy==1.24.4; python_version<\"3.9\"\nnumpy>=1.20; python_version>=\"3.9\"\n"), 0o644)
	res := runWithResults(t, root, requirementsResult(t, root, "numpy@1.24.4", "numpy@1.20"))
	var vers []string
	for _, f := range res.Findings {
		if f.Location == "requirements.txt" {
			vers = append(vers, f.Evidence)
		}
	}
	if len(vers) != 1 || !strings.HasPrefix(vers[0], "numpy@1.24.4 ") {
		t.Errorf("only the pinned version must stay: %v", vers)
	}
	if w := warnWith(res.Warnings, subUnpinned); !strings.Contains(w, "numpy") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	if warnWith(res.Warnings, subUnconfirmed) != "" {
		t.Errorf("numpy is already named; no duplicate: %v", res.Warnings)
	}
}

func TestDepsDashRSameNameRangeDropped(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("-r base.txt\nnumpy==1.24.4\n"), 0o644)
	os.WriteFile(filepath.Join(root, "base.txt"), []byte("numpy>=1.20\n"), 0o644)
	res := runWithResults(t, root, requirementsResult(t, root, "numpy@1.24.4", "numpy@1.20"))
	got := 0
	for _, f := range res.Findings {
		if f.Location == "requirements.txt" {
			got++
			if !strings.HasPrefix(f.Evidence, "numpy@1.24.4 ") {
				t.Errorf("unexpected kept: %s", f.Evidence)
			}
		}
	}
	if got != 1 {
		t.Errorf("kept %d", got)
	}
	if !strings.Contains(warnWith(res.Warnings, subUnpinned), "numpy") || warnWith(res.Warnings, subUnconfirmed) != "" {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDepsPinnedNameDifferentVersionNamed(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("numpy==1.24.4\n"), 0o644)
	res := runWithResults(t, root, requirementsResult(t, root, "numpy@9.9"))
	if countAt(res.Findings, "requirements.txt")["numpy"] != 0 {
		t.Error("version not pinned in the file must be dropped")
	}
	if w := warnWith(res.Warnings, subUnconfirmed); !strings.Contains(w, ": numpy (") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDepsSkippedDirRequirementsNamed(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "build"), 0o755)
	os.WriteFile(filepath.Join(root, "build", "requirements.txt"), []byte("numpy>=1.2\n"), 0o644)
	res := runWithResults(t, root, reqResultAt(t, root, "build/requirements.txt", "numpy@1.2"))
	if countAt(res.Findings, "build/requirements.txt")["numpy"] != 0 {
		t.Error("must be dropped")
	}
	if warnWith(res.Warnings, subUnpinned) != "" {
		t.Errorf("build/ is not walked: %v", res.Warnings)
	}
	if w := warnWith(res.Warnings, subUnconfirmed); !strings.Contains(w, ": numpy (") {
		t.Errorf("dropped finding must be named: %v", res.Warnings)
	}
}

func TestDepsNameOnlyLineNamedOnce(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("pytest\n"), 0o644)
	res := runWithResults(t, root, requirementsResult(t, root, "pytest@"))
	if !strings.Contains(warnWith(res.Warnings, subUnpinned), "pytest") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	if warnWith(res.Warnings, subUnconfirmed) != "" {
		t.Errorf("pytest must not be named twice: %v", res.Warnings)
	}
}

// aliasVuln is an advisory with the given aliases, summary and CVSS vector.
func aliasVuln(id, summary, vector string, aliases ...string) *osvschema.Vulnerability {
	v := vulnWith()
	if vector != "" {
		v = vulnWith(vector)
	}
	v.Id, v.Summary, v.Aliases = id, summary, aliases
	return v
}

// aliasResults reports vulns for one package in root/rel.
func aliasResults(root, rel, pkg string, vulns ...*osvschema.Vulnerability) models.PackageSource {
	var ids []string
	for _, v := range vulns {
		ids = append(ids, v.GetId())
	}
	return models.PackageSource{
		Source: models.SourceInfo{Path: filepath.Join(root, rel), Type: "lockfile"},
		Packages: []models.PackageVulns{{
			Package:         models.PackageInfo{Name: pkg, Version: "1.0.0", Ecosystem: "npm"},
			Vulnerabilities: vulns,
			Groups:          []models.GroupInfo{{IDs: ids}},
		}},
	}
}

const (
	cvssHigh   = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	cvssMedium = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
)

func TestDepsMergesAliasedAdvisories(t *testing.T) {
	root := t.TempDir()
	res := runWithResults(t, root, models.VulnerabilityResults{Results: []models.PackageSource{
		aliasResults(root, "package-lock.json", "requests",
			aliasVuln("PYSEC-1", "", cvssMedium, "CVE-2024-1", "GHSA-a"),
			aliasVuln("GHSA-a", "요약", cvssMedium, "CVE-2024-1", "PYSEC-1"),
			aliasVuln("GHSA-b", "다른 취약점", cvssMedium, "CVE-2024-2")),
	}})
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(res.Findings), res.Findings)
	}
	f := byID(res.Findings, "GHSA-a")
	if f == nil {
		t.Fatalf("GHSA id should represent the merged finding: %+v", res.Findings)
	}
	if !strings.Contains(f.Title, "요약") {
		t.Errorf("Title = %q", f.Title)
	}
	for _, want := range []string{"CVE-2024-1", "https://osv.dev/vulnerability/GHSA-a", "https://osv.dev/vulnerability/PYSEC-1"} {
		if !slices.Contains(f.References, want) {
			t.Errorf("References = %v, missing %s", f.References, want)
		}
	}
}

func TestDepsMergeLinksThroughSharedCVE(t *testing.T) {
	root := t.TempDir()
	res := runWithResults(t, root, models.VulnerabilityResults{Results: []models.PackageSource{
		aliasResults(root, "package-lock.json", "requests",
			aliasVuln("PYSEC-1", "", "", "CVE-2024-1"),
			aliasVuln("OTHER-1", "", "", "CVE-2024-2"),
			aliasVuln("GHSA-a", "요약", "", "CVE-2024-1", "CVE-2024-2")),
	}})
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
}

func TestDepsMergeKeepsHighestSeverity(t *testing.T) {
	root := t.TempDir()
	res := runWithResults(t, root, models.VulnerabilityResults{Results: []models.PackageSource{
		aliasResults(root, "package-lock.json", "requests",
			aliasVuln("PYSEC-1", "", cvssHigh, "GHSA-a"),
			aliasVuln("GHSA-a", "요약", cvssMedium)),
	}})
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if f := res.Findings[0]; f.Severity != finding.High || !strings.Contains(f.Evidence, "CVSS 7.5") {
		t.Errorf("Severity = %v, Evidence = %q", f.Severity, f.Evidence)
	}
}

func TestDepsMergeKeepsKEVFromAnyAdvisory(t *testing.T) {
	root := t.TempDir()
	res := runWithResults(t, root, models.VulnerabilityResults{Results: []models.PackageSource{
		aliasResults(root, "package-lock.json", "requests",
			aliasVuln("PYSEC-1", "", "", "CVE-2021-44228", "GHSA-a"),
			aliasVuln("GHSA-a", "요약", "")),
	}})
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if f := res.Findings[0]; !f.Exploited || f.Severity != finding.Critical {
		t.Errorf("Exploited = %v, Severity = %v", f.Exploited, f.Severity)
	}
}

func TestDepsMergeUsesFixFromAnyAdvisory(t *testing.T) {
	root := t.TempDir()
	withFix := fixVuln("requests", "npm", "2.0.0")
	withFix.Id, withFix.Aliases = "PYSEC-1", []string{"GHSA-a"}
	res := runWithResults(t, root, models.VulnerabilityResults{Results: []models.PackageSource{
		aliasResults(root, "package-lock.json", "requests", withFix, aliasVuln("GHSA-a", "요약", "")),
	}})
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	if f := res.Findings[0]; !strings.Contains(f.Fix, "2.0.0") {
		t.Errorf("Fix = %q", f.Fix)
	}
}

func TestDepsDoesNotMergeAcrossPackagesOrFiles(t *testing.T) {
	root := t.TempDir()
	v := func() *osvschema.Vulnerability { return aliasVuln("GHSA-a", "요약", "", "CVE-2024-1") }
	res := runWithResults(t, root, models.VulnerabilityResults{Results: []models.PackageSource{
		aliasResults(root, "package-lock.json", "a", v()),
		aliasResults(root, "package-lock.json", "b", v()),
		aliasResults(root, "web/package-lock.json", "a", v()),
	}})
	if len(res.Findings) != 3 {
		t.Fatalf("findings = %d, want 3: %+v", len(res.Findings), res.Findings)
	}
}

func TestDepsRecordsExternalData(t *testing.T) {
	t0 := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	const offlineNote = "오프라인 DB라 데이터 시점을 알 수 없음"
	type want struct {
		mode, status string
		at           *time.Time
		note         string
	}
	cases := []struct {
		name      string
		offline   bool
		dbPath    string
		scanErr   error
		kevErr    error
		wantErr   bool
		osv, kevW want
	}{
		{"온라인, KEV 성공", false, "", nil, nil, false,
			want{checker.ModeOnline, checker.ExternalUsed, &t0, ""}, want{checker.ModeOnline, checker.ExternalUsed, &t0, ""}},
		{"온라인, KEV 실패", false, "", nil, errors.New("blocked"), false,
			want{checker.ModeOnline, checker.ExternalUsed, &t0, ""}, want{checker.ModeOnline, checker.ExternalFailed, nil, ""}},
		{"OSV 실패", false, "", osvscanner.ErrAPIFailed, nil, true,
			want{checker.ModeOnline, checker.ExternalFailed, nil, ""}, want{checker.ModeOnline, checker.ExternalSkipped, nil, ""}},
		{"잠금 파일 없음", false, "", osvscanner.ErrNoPackagesFound, nil, false,
			want{checker.ModeOnline, checker.ExternalSkipped, nil, ""}, want{checker.ModeOnline, checker.ExternalSkipped, nil, ""}},
		{"오프라인 DB 있음", true, "/db", nil, nil, false,
			want{checker.ModeOffline, checker.ExternalUsed, nil, offlineNote}, want{checker.ModeOffline, checker.ExternalSkipped, nil, ""}},
		{"오프라인 DB 없음", true, "", nil, nil, true,
			want{checker.ModeOffline, checker.ExternalSkipped, nil, ""}, want{checker.ModeOffline, checker.ExternalSkipped, nil, ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			c := New(testFS, Options{
				OfflineDBPath: tc.dbPath,
				Now:           func() time.Time { return t0 },
				Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
					if tc.scanErr == osvscanner.ErrNoPackagesFound {
						return models.VulnerabilityResults{}, tc.scanErr
					}
					return loadResults(t, root), tc.scanErr
				},
				FetchKEV: func(context.Context) (*kev.Catalog, error) {
					if tc.kevErr != nil {
						return nil, tc.kevErr
					}
					return loadKEV(t), nil
				},
			})
			res, err := c.Run(context.Background(), checker.Target{Root: root, Offline: tc.offline})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(res.External) != 2 {
				t.Fatalf("External = %+v", res.External)
			}
			for i, w := range []struct {
				name string
				w    want
			}{{"OSV", tc.osv}, {"CISA KEV", tc.kevW}} {
				g := res.External[i]
				if g.Name != w.name || g.Mode != w.w.mode || g.Status != w.w.status || g.Note != w.w.note {
					t.Errorf("External[%d] = %+v, want %s %+v", i, g, w.name, w.w)
				}
				if (g.FetchedAt == nil) != (w.w.at == nil) || (g.FetchedAt != nil && !g.FetchedAt.Equal(*w.w.at)) {
					t.Errorf("External[%d].FetchedAt = %v, want %v", i, g.FetchedAt, w.w.at)
				}
			}
		})
	}
}

const malFix = "이 패키지를 제거하세요. 이미 설치했다면 그 컴퓨터에 있던 키와 토큰을 유출된 것으로 보고 교체하세요."

var malFS = fstest.MapFS{
	"explain/kinds/vuln-lib.md":      {Data: []byte("취약한 라이브러리 설명")},
	"explain/kinds/kev-lib.md":       {Data: []byte("실제 공격 중 설명")},
	"explain/kinds/malicious-lib.md": {Data: []byte("악성 패키지 설명")},
}

func runMal(t *testing.T, root string, offline bool, vulns ...*osvschema.Vulnerability) checker.Result {
	t.Helper()
	c := New(malFS, Options{
		OfflineDBPath: "/db",
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			return models.VulnerabilityResults{Results: []models.PackageSource{
				aliasResults(root, "package-lock.json", "op-vscode", vulns...)}}, nil
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root, Offline: offline})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func checkMal(t *testing.T, f finding.Finding) {
	t.Helper()
	if f.Severity != finding.Critical || f.Kind != "malicious-lib" {
		t.Errorf("severity/kind = %v / %q", f.Severity, f.Kind)
	}
	if f.Fix != malFix {
		t.Errorf("Fix = %q", f.Fix)
	}
	if f.Title != "악성 패키지: op-vscode@1.0.0: Malicious code in op-vscode (npm)" {
		t.Errorf("Title = %q", f.Title)
	}
	if f.Evidence != "op-vscode@1.0.0 (악성 패키지)" {
		t.Errorf("Evidence = %q", f.Evidence)
	}
	if f.ExplainKo != "악성 패키지 설명" {
		t.Errorf("ExplainKo = %q", f.ExplainKo)
	}
}

func TestDepsMaliciousByID(t *testing.T) {
	root := t.TempDir()
	res := runMal(t, root, false, aliasVuln("MAL-2025-342", "Malicious code in op-vscode (npm)", "", "SNYK-JS-OPVSCODE-8660173"))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	checkMal(t, res.Findings[0])
}

func TestDepsMaliciousByAlias(t *testing.T) {
	root := t.TempDir()
	res := runMal(t, root, false,
		aliasVuln("GHSA-mh79-jr8w-w349", "Malicious code in op-vscode (npm)", "", "MAL-2025-342"),
		aliasVuln("MAL-2025-342", "", "", "GHSA-mh79-jr8w-w349"))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	checkMal(t, res.Findings[0])
	// alias only: the GHSA record is the sole member and names MAL- as an alias
	res = runMal(t, root, false, aliasVuln("GHSA-mh79-jr8w-w349", "Malicious code in op-vscode (npm)", "", "MAL-2025-342"))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	checkMal(t, res.Findings[0])
}

func TestDepsMaliciousBeatsKEV(t *testing.T) {
	root := t.TempDir()
	res := runMal(t, root, false, aliasVuln("MAL-2025-342", "Malicious code in op-vscode (npm)", "", "CVE-2021-44228"))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	f := res.Findings[0]
	checkMal(t, f)
	if !f.Exploited {
		t.Error("Exploited must stay true when KEV also applies")
	}
}

func TestDepsNormalVulnUnchanged(t *testing.T) {
	root := t.TempDir()
	res := runMal(t, root, false, aliasVuln("GHSA-xxxx-yyyy-zzzz", "요약", cvssHigh, "CVE-2024-1"))
	f := res.Findings[0]
	if f.Kind != "vuln-lib" || f.Severity != finding.High || f.Exploited || f.ExplainKo != "취약한 라이브러리 설명" ||
		f.Title != "op-vscode@1.0.0: 요약" || f.Fix == malFix || !strings.Contains(f.Evidence, "CVSS 7.5") {
		t.Errorf("normal finding changed: %+v", f)
	}
}

func TestDepsOfflineMaliciousWarning(t *testing.T) {
	root := t.TempDir()
	v := aliasVuln("GHSA-xxxx-yyyy-zzzz", "요약", cvssHigh)
	off := runMal(t, root, true, v)
	if !slices.Contains(off.Warnings, warnMalOffline) {
		t.Errorf("offline warnings = %v", off.Warnings)
	}
	for _, e := range off.External {
		if e.Name == nameOSV && e.Status != checker.ExternalUsed {
			t.Errorf("OSV status changed: %+v", e)
		}
	}
	on := runMal(t, root, false, v)
	if slices.Contains(on.Warnings, warnMalOffline) {
		t.Errorf("online must not warn: %v", on.Warnings)
	}
}

// A MAL- record joined to an ordinary advisory through a shared alias stays
// malicious: the fix is removal even though the summary comes from the other one.
func TestDepsMaliciousMergedWithOrdinaryAdvisory(t *testing.T) {
	root := t.TempDir()
	res := runMal(t, root, false,
		aliasVuln("GHSA-aaaa-bbbb-cccc", "Ordinary summary", "", "CVE-2099-1"),
		aliasVuln("MAL-2099-2", "", "", "CVE-2099-1"))
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != "malicious-lib" || f.Fix != malFix {
		t.Errorf("kind = %q, fix = %q", f.Kind, f.Fix)
	}
	if !strings.Contains(f.Title, "Ordinary summary") || !strings.HasPrefix(f.Title, "악성 패키지: ") {
		t.Errorf("title = %q", f.Title)
	}
}
