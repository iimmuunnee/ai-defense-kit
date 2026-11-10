// Package deps checks lockfile dependencies against OSV and marks CVEs that
// are in the CISA KEV catalog. osv-scanner types never leave this package.
package deps

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/kev"
)

const (
	warnKEVFailed     = "KEV 목록을 받지 못해 '실제 공격 중' 표시를 하지 못했습니다."
	warnNoLockfile    = "의존성 잠금 파일을 찾지 못해 라이브러리 점검을 하지 못했습니다."
	warnKEVOffline    = "오프라인 모드라 KEV 목록을 확인하지 않았습니다."
	warnMalOffline    = "악성 패키지 점검은 오프라인 DB 내용에 달려 있습니다."
	warnReqUnreadable = "%s 파일을 읽지 못해 버전을 정확히 고정했는지 확인하지 못했습니다."
	fixMulti          = "여러 버전대에 고친 버전이 있습니다. 원문 링크에서 내 버전에 맞는 버전을 확인하세요."
	fixMalicious      = "이 패키지를 제거하세요. 이미 설치했다면 그 컴퓨터에 있던 키와 토큰을 유출된 것으로 보고 교체하세요."
	fixNone           = "아직 고친 버전이 없습니다. 원문 링크를 확인하세요."
)

// ScanFunc runs the OSV scan. Tests inject a fake.
type ScanFunc func(osvscanner.ScannerActions) (models.VulnerabilityResults, error)

// Options configures the checker; zero values use the real network-backed parts.
type Options struct {
	Scan          ScanFunc
	FetchKEV      func(ctx context.Context) (*kev.Catalog, error)
	OfflineDBPath string
	Now           func() time.Time // nil means time.Now
	// NewOverride makes the empty config file used under --untrusted and returns
	// its path. nil means newEmptyOverride.
	NewOverride func() (string, error)
}

type scanOut struct {
	res models.VulnerabilityResults
	err error
}

type depsChecker struct {
	data fs.FS
	opt  Options
}

// New returns the dependency checker. data supplies explain/kinds/*.md.
func New(data fs.FS, opt Options) checker.Checker {
	if opt.Scan == nil {
		opt.Scan = osvscanner.DoScan
	}
	if opt.FetchKEV == nil {
		opt.FetchKEV = func(ctx context.Context) (*kev.Catalog, error) {
			return kev.Fetch(ctx, http.DefaultClient, kev.DefaultURL)
		}
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.NewOverride == nil {
		opt.NewOverride = newEmptyOverride
	}
	return depsChecker{data: data, opt: opt}
}

func (depsChecker) Name() string { return "deps" }

const (
	nameOSV = "OSV"
	nameKEV = "CISA KEV"

	noteOfflineDB = "오프라인 DB라 데이터 시점을 알 수 없음"
)

// external builds the OSV and KEV records. FetchedAt is set only for a
// fresh online fetch: an offline DB has no known fetch time.
func external(offline bool, osv, kevStatus string, osvAt, kevAt *time.Time) []checker.ExternalData {
	mode := checker.ModeOnline
	if offline {
		mode = checker.ModeOffline
	}
	o := checker.ExternalData{Name: nameOSV, Mode: mode, Status: osv, FetchedAt: osvAt}
	if offline && osv == checker.ExternalUsed {
		o.Note = noteOfflineDB
	}
	return []checker.ExternalData{o, {Name: nameKEV, Mode: mode, Status: kevStatus, FetchedAt: kevAt}}
}

func (c depsChecker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	skipped := external(t.Offline, checker.ExternalSkipped, checker.ExternalSkipped, nil, nil)
	if t.Offline && c.opt.OfflineDBPath == "" {
		return checker.Result{External: skipped}, fmt.Errorf("%w: 오프라인 DB 경로가 없어 건너뜀", checker.ErrSkipped)
	}
	root, err := filepath.Abs(t.Root)
	if err != nil {
		return checker.Result{External: skipped}, err
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r // absolute Source.Paths from the scanner are resolved the same way
	}
	if err := ctx.Err(); err != nil {
		return checker.Result{External: skipped}, err
	}

	actions := osvscanner.ScannerActions{
		DirectoryPaths: []string{root},
		Recursive:      true,
	}
	actions.TransitiveScanning.Disabled = true // no extra lookups (deps.dev etc.)
	// The vendored C/C++ extractor sends file paths and MD5 hashes to
	// api.osv.dev; OSV must receive package names, versions and ecosystems only.
	actions.PluginsDisabled = append(actions.PluginsDisabled, "filesystem/vendored")
	if t.Offline {
		actions.CompareOffline = true
		actions.LocalDBPath = c.opt.OfflineDBPath
	}
	if t.Untrusted {
		actions.NoIgnore = true // the repository's .gitignore must not hide its lockfiles
		path, err := c.opt.NewOverride()
		if err != nil {
			return checker.Result{External: skipped}, overrideFailure(err)
		}
		defer os.Remove(path)
		if isInside(root, path) {
			return checker.Result{External: skipped}, overrideFailure(errOverrideInRoot)
		}
		actions.ConfigOverridePath = path
	}

	out, logged := quietScan(c.opt.Scan, actions)
	logged = hideOverride(logged, actions.ConfigOverridePath)
	results, err := out.res, out.err
	noPackages := errors.Is(err, osvscanner.ErrNoPackagesFound)
	failed := external(t.Offline, checker.ExternalFailed, checker.ExternalSkipped, nil, nil)
	if logged != "" {
		// osv-scanner logs lookup and extraction failures instead of returning
		// them; treat them as a failure so it never looks like "no vulnerable
		// dependencies".
		if noPackages {
			return checker.Result{External: failed}, fmt.Errorf("의존성 잠금 파일을 읽지 못했습니다: %s", logged)
		}
		return checker.Result{External: failed}, fmt.Errorf("OSV 취약점 DB 조회에 실패했습니다: %s", logged)
	}
	switch {
	case err == nil, errors.Is(err, osvscanner.ErrVulnerabilitiesFound):
	case noPackages:
		return checker.Result{
			Warnings: slices.Concat([]string{warnNoLockfile}, requirementWarnings(root, newReqState()), lockfileWarnings(root)),
			External: skipped,
		}, nil
	default:
		if actions.ConfigOverridePath != "" {
			err = errors.New(hideOverride(err.Error(), actions.ConfigOverridePath))
		}
		return checker.Result{External: failed}, fmt.Errorf("OSV 취약점 DB 조회에 실패했습니다: %w", err)
	}

	var res checker.Result
	var catalog *kev.Catalog
	var osvAt *time.Time
	if !t.Offline {
		now := c.opt.Now()
		osvAt = &now
	}
	switch {
	case t.Offline:
		res.Warnings = append(res.Warnings, warnKEVOffline, warnMalOffline)
		res.External = external(true, checker.ExternalUsed, checker.ExternalSkipped, nil, nil)
	default:
		var kevErr error
		if catalog, kevErr = c.opt.FetchKEV(ctx); kevErr != nil {
			catalog = nil
			res.External = external(false, checker.ExternalUsed, checker.ExternalFailed, osvAt, nil)
			if ctx.Err() != nil {
				return checker.Result{External: res.External}, ctx.Err()
			}
			res.Warnings = append(res.Warnings, warnKEVFailed)
		} else {
			kevAt := c.opt.Now()
			res.External = external(false, checker.ExternalUsed, checker.ExternalUsed, osvAt, &kevAt)
		}
	}

	explainVuln := c.explain("vuln-lib.md")
	explainKEV := c.explain("kev-lib.md")
	explainMal := c.explain("malicious-lib.md")

	flat, err := flatten(results)
	if err != nil {
		return checker.Result{External: res.External}, err
	}
	rs := newReqState()
	advisories := newAdvisorySet()
	for _, fl := range flat {
		if fl.Vulnerability == nil { // license or deprecation entries
			continue
		}
		if !keepRequirementFinding(root, fl, rs) {
			continue
		}
		loc := finding.NormalizePath(root, sourcePath(root, fl.Source.Path))
		advisories.add(loc, fl.Package, fl.Vulnerability)
	}
	for _, g := range advisories.groups {
		if len(g.vulns) == 0 { // merged into another group
			continue
		}
		loc, pkg := g.loc, g.pkg.Name+"@"+g.pkg.Version
		v := mergeAdvisories(g.vulns)

		cves := cveIDs(v)
		sev, memo := severityOf(v)
		exploited := false
		for _, cve := range cves {
			if catalog.Has(cve) {
				exploited = true
				break
			}
		}
		explain, kind := explainVuln, "vuln-lib"
		if exploited {
			sev, memo, explain, kind = finding.Critical, "KEV: 실제 공격 중", explainKEV, "kev-lib"
		}

		title, fix := pkg+": "+titleText(v), fixFor(v, g.pkg)
		if isMalicious(g.vulns) {
			// malicious wins over KEV; Exploited stays as KEV set it
			sev, memo, explain, kind = finding.Critical, "악성 패키지", explainMal, "malicious-lib"
			title, fix = "악성 패키지: "+title, fixMalicious
		}

		refs := append([]string{}, cves...)
		for _, member := range g.vulns {
			refs = append(refs, "https://osv.dev/vulnerability/"+member.GetId())
		}
		res.Findings = append(res.Findings, finding.Finding{
			ID:          v.GetId(),
			Source:      "deps",
			Kind:        kind,
			Severity:    sev,
			Exploited:   exploited,
			Confidence:  finding.Certain,
			Location:    loc,
			Evidence:    pkg + " (" + memo + ")",
			Title:       title,
			ExplainKo:   explain,
			Fix:         fix,
			References:  refs,
			Fingerprint: finding.MakeFingerprint(v.GetId(), loc, pkg),
		})
	}
	res.Warnings = slices.Concat(res.Warnings, requirementWarnings(root, rs), lockfileWarnings(root))
	return res, nil
}

// advisoryGroup is one vulnerability of one package in one file. OSV can list
// it under several IDs (GHSA, PYSEC) that name each other as aliases.
type advisoryGroup struct {
	loc   string
	pkg   models.PackageInfo
	vulns []*osvschema.Vulnerability
}

// advisorySet groups advisories that share an ID or alias, directly or through
// another advisory. A group emptied by a merge stays in groups and is skipped.
type advisorySet struct {
	groups []*advisoryGroup
	owners map[string]*advisoryGroup
}

func newAdvisorySet() *advisorySet {
	return &advisorySet{owners: map[string]*advisoryGroup{}}
}

func (s *advisorySet) add(loc string, pkg models.PackageInfo, v *osvschema.Vulnerability) {
	key := func(id string) string {
		return loc + "\x00" + pkg.Name + "@" + pkg.Version + "\x00" + id
	}
	var g *advisoryGroup
	for _, id := range advisoryIDs(v) {
		o := s.owners[key(id)]
		if o == nil || o == g {
			continue
		}
		if g == nil {
			g = o
			continue
		}
		// v links two groups found so far
		for _, member := range o.vulns {
			for _, memberID := range advisoryIDs(member) {
				s.owners[key(memberID)] = g
			}
		}
		g.vulns = append(g.vulns, o.vulns...)
		o.vulns = nil
	}
	if g == nil {
		g = &advisoryGroup{loc: loc, pkg: pkg}
		s.groups = append(s.groups, g)
	}
	if !slices.ContainsFunc(g.vulns, func(m *osvschema.Vulnerability) bool { return m.GetId() == v.GetId() }) {
		g.vulns = append(g.vulns, v)
	}
	for _, id := range advisoryIDs(v) {
		s.owners[key(id)] = g
	}
}

// isMalicious reports whether any member's ID or alias is an OSV malicious
// package advisory (MAL-). The representative ID can be a GHSA.
func isMalicious(vulns []*osvschema.Vulnerability) bool {
	for _, v := range vulns {
		for _, id := range advisoryIDs(v) {
			if strings.HasPrefix(id, "MAL-") {
				return true
			}
		}
	}
	return false
}

func advisoryIDs(v *osvschema.Vulnerability) []string {
	return append([]string{v.GetId()}, v.GetAliases()...)
}

// mergeAdvisories sorts vulns and combines them into one advisory. The ID must
// not depend on the scanner's order, because the fingerprint in .adkignore is
// built from it: GHSA comes first, since PYSEC entries can lack a summary.
func mergeAdvisories(vulns []*osvschema.Vulnerability) *osvschema.Vulnerability {
	slices.SortFunc(vulns, func(a, b *osvschema.Vulnerability) int {
		aGHSA, bGHSA := strings.HasPrefix(a.GetId(), "GHSA-"), strings.HasPrefix(b.GetId(), "GHSA-")
		switch {
		case aGHSA && !bGHSA:
			return -1
		case !aGHSA && bGHSA:
			return 1
		}
		return strings.Compare(a.GetId(), b.GetId())
	})
	merged := &osvschema.Vulnerability{Id: vulns[0].GetId()}
	for _, v := range vulns {
		if merged.Summary == "" {
			merged.Summary = strings.TrimSpace(v.GetSummary())
		}
		merged.Aliases = append(merged.Aliases, advisoryIDs(v)...)
		merged.Severity = append(merged.Severity, v.GetSeverity()...)
		merged.Affected = append(merged.Affected, v.GetAffected()...)
	}
	return merged
}

// sourcePath resolves symlinks in the directory of an absolute scanner path so
// that it matches the resolved root.
func sourcePath(root, p string) string {
	if filepath.IsAbs(p) {
		// resolve the directory only: a symlinked file itself must stay
		// visible so it is not trusted as a requirements file
		if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			return filepath.Join(r, filepath.Base(p))
		}
	}
	return p
}

// reqState carries what the requirements filter learned during one run.
type reqState struct {
	trees   map[string]*reqTree
	dropped map[string]bool // names of dropped requirements findings
}

type reqTree struct {
	exact      map[string]bool // name + "\x00" + pinned version
	unreadable []string
}

func newReqState() *reqState {
	return &reqState{trees: map[string]*reqTree{}, dropped: map[string]bool{}}
}

func pinKey(name, version string) string { return name + "\x00" + version }

// keepRequirementFinding reports whether a finding should be kept. Findings
// from requirements files are kept only when the reported (name, version) is
// pinned exactly in the file or the files it includes with -r (scalibr follows
// them): for the rest it reports the lowest allowed version or none, which is
// not the version that gets installed. A name can be listed more than once
// (environment markers, -r), so the version must match too. Dropped findings
// are named in a warning, never dropped silently.
func keepRequirementFinding(root string, fl models.VulnerabilityFlattened, rs *reqState) bool {
	src := sourcePath(root, fl.Source.Path)
	if !isRequirementsFile(filepath.Base(src)) {
		return true
	}
	path := src
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	tr, ok := rs.trees[path]
	if !ok {
		tr = &reqTree{exact: map[string]bool{}}
		reqs, bad := loadRequirementsTree(root, path)
		tr.unreadable = bad
		for _, r := range reqs {
			if r.Exact {
				tr.exact[pinKey(r.Name, r.Version)] = true
			}
		}
		rs.trees[path] = tr
	}
	name := normalizeName(fl.Package.Name)
	if v := strings.TrimSpace(fl.Package.Version); v != "" && tr.exact[pinKey(name, v)] {
		return true
	}
	rs.dropped[name] = true
	return false
}

// requirementWarnings builds the requirements warnings: unreadable files,
// unpinned libraries found by walking the repository, and other libraries
// whose findings were dropped because their pin could not be confirmed.
func requirementWarnings(root string, rs *reqState) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if w := fmt.Sprintf(warnReqUnreadable, finding.NormalizePath(root, p)); !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	names, unreadable := unpinnedNames(root)
	paths := make([]string, 0, len(rs.trees))
	for p := range rs.trees {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		for _, u := range rs.trees[p].unreadable {
			add(u)
		}
	}
	for _, u := range unreadable {
		add(u)
	}
	if len(names) > 0 {
		out = append(out, unpinnedWarning(names))
	}
	// dropped names already in the unpinned warning are not repeated; the
	// rest (version not pinned in the file, unreadable file, empty version,
	// file in a directory the walk skips) are named here
	named := map[string]bool{}
	for _, n := range names {
		named[n] = true
	}
	var un []string
	for n := range rs.dropped {
		if !named[n] {
			un = append(un, n)
		}
	}
	if len(un) > 0 {
		sort.Strings(un)
		out = append(out, "requirements 파일에서 고정 여부를 확인할 수 없는 라이브러리는 결과에서 뺐습니다: "+nameList(un)+" (직접 확인해 주세요)")
	}
	return out
}

// nameList joins up to 10 names, then "외 N개".
func nameList(names []string) string {
	if len(names) > 10 {
		return strings.Join(names[:10], ", ") + fmt.Sprintf(" 외 %d개", len(names)-10)
	}
	return strings.Join(names, ", ")
}

// unpinnedWarning names up to 10 libraries.
func unpinnedWarning(names []string) string {
	return "requirements.txt에서 버전을 정확히 고정하지 않은 라이브러리는 버전을 알 수 없어 확인하지 못했습니다: " +
		nameList(names) + ` ("==" 로 고정하면 점검할 수 있습니다)`
}

func titleText(v *osvschema.Vulnerability) string {
	if s := strings.TrimSpace(v.GetSummary()); s != "" {
		return s
	}
	return v.GetId()
}

// flatten turns a panic inside osv-scanner's result handling into an error.
func flatten(r models.VulnerabilityResults) (out []models.VulnerabilityFlattened, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("의존성 조회 결과를 해석하지 못했습니다: %v", p)
		}
	}()
	return r.Flatten(), nil
}

func cveIDs(v *osvschema.Vulnerability) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{v.GetId()}, v.GetAliases()...) {
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// fixFor picks the upgrade target for the installed version: the lowest fixed
// version above it among affected entries for the same package and ecosystem.
// When versions cannot be compared reliably and several fixes exist, it points
// the reader to the advisory instead of guessing.
func fixFor(v *osvschema.Vulnerability, pkg models.PackageInfo) string {
	var fixed []string
	seen := map[string]bool{}
	for _, a := range v.GetAffected() {
		if a.GetPackage().GetName() != pkg.Name || !sameEcosystem(a.GetPackage().GetEcosystem(), pkg.Ecosystem) {
			continue
		}
		for _, r := range a.GetRanges() {
			for _, e := range r.GetEvents() {
				if f := e.GetFixed(); f != "" && !seen[f] {
					seen[f] = true
					fixed = append(fixed, f)
				}
			}
		}
	}
	switch len(fixed) {
	case 0:
		return fixNone
	case 1:
		return fixed[0] + " 이상으로 올리세요"
	}
	inst, ok := parseVersion(pkg.Version)
	best := ""
	var bestV []int
	for _, f := range fixed {
		fv, fok := parseVersion(f)
		if !ok || !fok {
			return fixMulti
		}
		if compareVersions(fv, inst) > 0 && (best == "" || compareVersions(fv, bestV) < 0) {
			best, bestV = f, fv
		}
	}
	if best == "" {
		return fixMulti
	}
	return best + " 이상으로 올리세요"
}

func sameEcosystem(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	a, _, _ = strings.Cut(a, ":")
	b, _, _ = strings.Cut(b, ":")
	return strings.EqualFold(a, b)
}

// parseVersion reads the leading dotted numbers of a version ("v1.2.3-rc1" ->
// [1 2 3]). It reports false when no number can be read.
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	var out []int
	for _, part := range strings.Split(s, ".") {
		end := 0
		for end < len(part) && part[end] >= '0' && part[end] <= '9' {
			end++
		}
		if end == 0 {
			break
		}
		n, err := strconv.Atoi(part[:end])
		if err != nil {
			return nil, false
		}
		out = append(out, n)
		if end < len(part) {
			break
		}
	}
	return out, len(out) > 0
}

func compareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (c depsChecker) explain(name string) string {
	if c.data == nil {
		return ""
	}
	b, err := fs.ReadFile(c.data, "explain/kinds/"+name)
	if err != nil {
		return ""
	}
	return string(b)
}
