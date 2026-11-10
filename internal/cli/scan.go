package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/autorun"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/cicd"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/deps"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker/supabase"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/ignore"
	"github.com/iimmuunnee/ai-defense-kit/internal/kev"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
	"github.com/iimmuunnee/ai-defense-kit/internal/rules"
	"github.com/iimmuunnee/ai-defense-kit/internal/safeio"
	"github.com/iimmuunnee/ai-defense-kit/internal/stack"
)

const (
	checkerTimeout = 5 * time.Minute
	kevTimeout     = 30 * time.Second
	msgCancelled   = "사용자가 점검을 중단했습니다."
	usageText      = `사용법:
  adk version
  adk scan <폴더> [--format md,json,sarif] [--out <폴더>] [--fail-on critical|high|medium|low|none]
                  [--strict] [--offline] [--osv-db <경로>] [--rules-dir <경로>] [--untrusted]
  adk assets <도메인> [--known <파일>] [--exclude-expired] [--format md,json] [--out <폴더>]
                    [--strict]
  adk watch init|check|accept <key> [--config <파일>] [--baseline <파일>] [--format md,json] [--out <폴더>]
                  [--fail-on critical|high|medium|low|none] [--baseline-sha256 <값>] [--every <주기>] [--note "<사유>"]
                  [--expect <항목=값>] [--allow-env-proxy]
  adk device [init|check|accept <key>...] [--format md,json,sarif] [--out <폴더>] [--fail-on critical|high|medium|low|none]
                  [--home <폴더>] [--path <PATH>] [--baseline <파일>] [--baseline-sha256 <값>] [--note "<사유>"]
`
)

type scanOptions struct {
	offline bool
	osvDB   string
}

// defaultCheckers builds the checker list. Tests replace it to avoid the network.
var defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
	return []checker.Checker{
		rules.NewChecker(data),
		supabase.New(data),
		autorun.New(data),
		cicd.New(data),
		secrets.New(data),
		deps.New(data, deps.Options{
			OfflineDBPath: opt.osvDB,
			FetchKEV: func(ctx context.Context) (*kev.Catalog, error) {
				ctx, cancel := context.WithTimeout(ctx, kevTimeout)
				defer cancel()
				return kev.Fetch(ctx, http.DefaultClient, kev.DefaultURL)
			},
		}),
	}
}

// Run executes the adk command line and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version", "--version":
		return runVersion(stdout)
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "assets":
		return runAssets(ctx, args[1:], stdout, stderr)
	case "watch":
		return runWatch(ctx, args[1:], stdout, stderr)
	case "device":
		return runDevice(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "알 수 없는 명령입니다: %s\n", args[0])
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var (
		format   = fl.String("format", "md", "")
		outDir   = fl.String("out", "", "")
		failOn   = fl.String("fail-on", "high", "")
		strict   = fl.Bool("strict", false, "")
		offline  = fl.Bool("offline", false, "")
		osvDB    = fl.String("osv-db", "", "")
		rulesDir = fl.String("rules-dir", "", "")
		untrust  = fl.Bool("untrusted", false, "")
	)
	positional, code, ok := parseArgs(fl, args, stdout, stderr)
	if !ok {
		return code
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "점검할 폴더를 하나만 지정하세요.")
		fmt.Fprint(stderr, usageText)
		return 2
	}

	formats, ok := outputFormats(*format, *outDir, stderr)
	if !ok {
		return 2
	}
	failSev, err := ParseFailOn(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, usageText)
		return 2
	}

	target := positional[0]
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		fmt.Fprintf(stderr, "점검할 폴더를 찾을 수 없습니다: %s\n", target)
		return 2
	}
	root, err := filepath.Abs(target)
	if err == nil {
		// A symlinked folder must be scanned as its real path: file walkers
		// do not descend into a symlinked root.
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		fmt.Fprintf(stderr, "폴더 경로를 확인하지 못했습니다: %v\n", err)
		return 2
	}

	var data fs.FS = aidefensekit.Data
	if *rulesDir != "" {
		if rs, err := os.Stat(*rulesDir); err != nil || !rs.IsDir() {
			fmt.Fprintf(stderr, "규칙 폴더를 찾을 수 없습니다: %s\n", *rulesDir)
			return 2
		}
		data = os.DirFS(*rulesDir)
	}
	// A broken rules file means no scan at all, not a quietly failed checker.
	loadedRules, err := rules.Load(data)
	if err != nil {
		fmt.Fprintf(stderr, "규칙 파일을 불러오지 못했습니다: %v\n", err)
		return 2
	}

	catalog, err := mapping.Load(data)
	if err != nil {
		fmt.Fprintf(stderr, "국내 기준 파일을 불러오지 못했습니다: %v\n", err)
		return 2
	}

	origin := report.OriginBuiltin
	if *rulesDir != "" {
		origin = report.OriginCustom
	}
	ruleSet, err := ruleData(data, origin, len(loadedRules))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	mapSet, err := mappingData(data, origin, catalog)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	stacks, err := stack.Detect(root)
	if err != nil {
		fmt.Fprintf(stderr, "스택을 확인하지 못했습니다: %v\n", err)
		return 2
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	t := checker.Target{Root: root, Stacks: stacks, Offline: *offline, Untrusted: *untrust}
	findings, checks := checker.RunAll(ctx, defaultCheckers(data, scanOptions{offline: *offline, osvDB: *osvDB}), t, checkerTimeout)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	for _, w := range catalog.Attach(findings) {
		fmt.Fprintf(stderr, "경고: %s\n", w)
	}

	return finishReport(func() report.Report {
		// Called before any report is written, so this run's own files cannot
		// make the repository look dirty.
		rep := report.Report{
			Target:       target,
			Stacks:       stacks,
			ScannedAt:    time.Now(),
			ToolVersion:  toolVersion(),
			GitCommit:    gitCommit(ctx, root),
			TargetName:   report.TargetName(root),
			GitDirty:     report.DirtyUnknown,
			Data:         report.DataVersions{Rules: ruleSet, Mappings: mapSet},
			ScanRoot:     root,
			PrivatePaths: scanPrivatePaths(root, target, *osvDB, *rulesDir),
		}
		// git is only asked when the answer is written somewhere.
		wantSARIF := slices.Contains(formats, "sarif")
		if *outDir != "" || wantSARIF {
			rep.GitDirty = gitDirty(ctx, root)
		}
		if wantSARIF {
			rep.RepoPrefix = gitPrefix(ctx, root)
		}
		if bi, ok := debug.ReadBuildInfo(); ok {
			rep.Components = report.Components(bi)
		}
		return rep
	}, findings, checks, root, outputOptions{formats: formats, outDir: *outDir, failOn: failSev, strict: *strict, untrusted: *untrust}, stdout, stderr)
}

// parseArgs parses fl, allowing flags before or after positional
// arguments. ok is false when the caller should return code.
func parseArgs(fl *flag.FlagSet, args []string, stdout, stderr io.Writer) (positional []string, code int, ok bool) {
	for {
		if err := fl.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(stdout, usageText)
				return nil, 0, false
			}
			fmt.Fprintf(stderr, "옵션 오류: %v\n", err)
			fmt.Fprint(stderr, usageText)
			return nil, 2, false
		}
		if fl.NArg() == 0 {
			return positional, 0, true
		}
		positional = append(positional, fl.Arg(0))
		args = fl.Args()[1:]
	}
}

// outputFormats checks --format and --out together. On error it prints the
// reason and usage and returns ok=false (exit code 2).
func outputFormats(format, outDir string, stderr io.Writer) ([]string, bool) {
	formats, err := parseFormats(format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, usageText)
		return nil, false
	}
	if len(formats) > 1 && outDir == "" {
		fmt.Fprintln(stderr, "형식을 둘 이상 고르면 --out으로 저장할 폴더를 지정해야 합니다.")
		fmt.Fprint(stderr, usageText)
		return nil, false
	}
	return formats, true
}

// outputOptions are the output and exit-code flags shared by scan and assets.
type outputOptions struct {
	formats []string
	outDir  string
	failOn  *finding.Severity
	strict  bool
	// untrusted leaves the scanned repository's .adkignore unread.
	untrusted bool
	// noIgnore skips .adkignore altogether and leaves Report.Untrusted false.
	noIgnore bool
	// alwaysReport writes the report even when every check failed: watch
	// lists each target it could not verify there.
	alwaysReport bool
	// exempt holds fingerprints of findings that are reported but do not
	// count toward the exit code: device check's credentials that were
	// already in the baseline.
	exempt map[string]bool
}

// outDirInside reports whether dir is root or lies under it, after links in the
// parts that exist have been resolved. A path that cannot be resolved counts
// as not inside.
func outDirInside(dir, root string) bool {
	resolve := func(p string) (string, bool) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", false
		}
		// Resolve the longest existing prefix; the rest may not exist yet.
		rest := ""
		for cur := abs; ; cur = filepath.Dir(cur) {
			if r, err := filepath.EvalSymlinks(cur); err == nil {
				return filepath.Join(r, rest), true
			}
			if filepath.Dir(cur) == cur {
				return "", false
			}
			rest = filepath.Join(filepath.Base(cur), rest)
		}
	}
	d, ok1 := resolve(dir)
	r, ok2 := resolve(root)
	if !ok1 || !ok2 {
		return false
	}
	rel, err := filepath.Rel(r, d)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// finishReport is the common tail of scan and assets: stop if no checker
// ran, warn about failed checks, drop findings listed in
// <ignoreRoot>/.adkignore (and their asset rows), write the reports and
// return the exit code. header builds the report's descriptive fields and is
// called only when a report will be written.
func finishReport(header func() report.Report, findings []finding.Finding, checks []checker.CheckStatus,
	ignoreRoot string, out outputOptions, stdout, stderr io.Writer) int {
	if !out.alwaysReport && !anyRan(checks) {
		fmt.Fprintln(stderr, "실행된 점검이 하나도 없습니다.")
		for _, c := range checks {
			fmt.Fprintf(stderr, "- %s: %s\n", c.Name, report.SafeText(c.Error))
		}
		return 2
	}
	warnChecks(stderr, checks)
	if out.untrusted && out.outDir != "" && outDirInside(out.outDir, ignoreRoot) {
		fmt.Fprintln(stderr, "경고: 출력 폴더가 점검하는 저장소 안에 있습니다. 저장소가 심어 둔 링크는 따라가지 않지만, 저장소 밖 폴더를 쓰는 편이 낫습니다.")
	}

	ignored := ignore.Set{}
	if !out.untrusted && !out.noIgnore {
		var err error
		if ignored, err = ignore.Load(ignoreRoot); err != nil {
			fmt.Fprintf(stderr, ".adkignore 파일을 읽지 못했습니다: %v\n", err)
			return 2
		}
	}
	kept := findings[:0:0]
	for _, f := range findings {
		if !ignored.Has(f.Fingerprint) {
			kept = append(kept, f)
		}
	}
	ignoredCount := len(findings) - len(kept)
	var hidden []finding.Finding
	if ignoredCount > 0 {
		for _, f := range findings {
			if ignored.Has(f.Fingerprint) {
				hidden = append(hidden, f)
			}
		}
		finding.Sort(hidden)
	}
	findings = kept

	finding.Sort(findings)
	rep := header()
	if ignoredCount > 0 && rep.Kind != report.KindAssets {
		fmt.Fprintln(stderr, "⚠️ 경고: "+report.HidingWarning(ignoredCount))
	}
	rep.Untrusted = out.untrusted
	rep.Findings = findings
	rep.Ignored = ignoredCount
	rep.IgnoredFindings = hidden
	rep.Checks = checks
	if rep.Assets != nil {
		rows := rep.Assets[:0:0]
		for _, a := range rep.Assets {
			if !ignored.Has(a.Fingerprint) {
				rows = append(rows, a)
			}
		}
		rep.Assets = rows
	}
	if err := writeReports(rep, out.formats, out.outDir, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "리포트를 쓰지 못했습니다: %v\n", err)
		return 2
	}
	counted := findings
	if len(out.exempt) > 0 {
		counted = nil
		for _, f := range findings {
			if !out.exempt[f.Fingerprint] {
				counted = append(counted, f)
			}
		}
	}
	return ExitCode(counted, checks, out.failOn, out.strict)
}

// warnChecks prints every failed or skipped check and every checker warning
// to the terminal, whatever the output format, so a partial scan never looks
// like a clean one.
func warnChecks(stderr io.Writer, checks []checker.CheckStatus) {
	var lines []string
	for _, c := range checks {
		switch c.Status {
		case checker.StatusFailed:
			lines = append(lines, fmt.Sprintf("  - %s (실패): %s", c.Name, report.SafeText(c.Error)))
		case checker.StatusSkipped:
			lines = append(lines, fmt.Sprintf("  - %s (건너뜀): %s", c.Name, report.SafeText(c.Error)))
		}
		for _, w := range c.Warnings {
			lines = append(lines, fmt.Sprintf("  - %s: %s", c.Name, report.SafeText(w)))
		}
	}
	if len(lines) > 0 {
		fmt.Fprintln(stderr, "⚠️ 경고: 일부 점검을 하지 못했습니다. 아래 항목은 결과에 빠져 있습니다.")
		fmt.Fprintln(stderr, strings.Join(lines, "\n"))
	}
	for _, c := range checks {
		for _, n := range c.Notes {
			fmt.Fprintf(stderr, "참고: %s: %s\n", c.Name, report.SafeText(n))
		}
	}
}

func anyRan(checks []checker.CheckStatus) bool {
	for _, c := range checks {
		if c.Status == checker.StatusOK {
			return true
		}
	}
	return false
}

func parseFormats(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "md" && f != "json" && f != "sarif" {
			return nil, fmt.Errorf("--format 값이 올바르지 않습니다: %q (md, json, sarif만 가능)", f)
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

func writeReports(rep report.Report, formats []string, outDir string, stdout, stderr io.Writer) error {
	write := func(f string, w io.Writer) error {
		switch f {
		case "json":
			return report.WriteJSON(w, rep)
		case "sarif":
			return report.WriteSARIF(w, rep)
		}
		return report.WriteMarkdown(w, rep)
	}
	if outDir == "" {
		return write(formats[0], stdout)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	evPath := filepath.Join(outDir, report.EvidenceFile)
	paths := []string{evPath}
	for _, f := range formats {
		paths = append(paths, filepath.Join(outDir, "adk-report."+f))
	}
	// Every path is checked before any is written, so a refused one leaves the
	// earlier files and the old evidence file as they were.
	for _, p := range paths {
		if err := safeio.Check(p); err != nil {
			return err
		}
	}
	// An evidence file from an earlier run must not outlive a failed rewrite:
	// it would describe reports that are no longer on disk.
	if err := os.Remove(evPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("이전 증적 파일을 지우지 못했습니다: %w", err)
	}
	// Only files written in this run are listed, hashed from the bytes on
	// disk after writing. The evidence file comes last and lists itself nowhere.
	var files []report.ReportFile
	for _, f := range formats {
		path := filepath.Join(outDir, "adk-report."+f)
		if err := safeio.WriteFile(path, reportPerm, func(w io.Writer) error { return write(f, w) }); err != nil {
			return err
		}
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		files = append(files, report.ReportFile{File: filepath.Base(path), SHA256: sum})
		fmt.Fprintf(stderr, "리포트를 저장했습니다: %s\n", path)
	}
	if err := safeio.WriteFile(evPath, reportPerm, func(w io.Writer) error { return report.WriteEvidence(w, rep, files) }); err != nil {
		return fmt.Errorf("증적 파일을 쓰지 못했습니다: %w", err)
	}
	fmt.Fprintf(stderr, "증적 파일을 저장했습니다: %s\n", evPath)
	return nil
}

// reportPerm is the mode of report and evidence files written under --out.
const reportPerm = 0o644

// gitCommit returns HEAD of the target repository, or "" if unavailable.
func gitCommit(ctx context.Context, root string) string {
	ctx, cancel := context.WithTimeout(ctx, gitStateTimeout)
	defer cancel()
	out, err := safeGitCmd(ctx, "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
