package cli

import (
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/rules"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

func sev(s finding.Severity) *finding.Severity { return &s }

func TestExitCode(t *testing.T) {
	high := []finding.Finding{{Severity: finding.High}}
	info := []finding.Finding{{Severity: finding.Info}}
	ok := []checker.CheckStatus{{Name: "rules", Status: checker.StatusOK}}
	failed := []checker.CheckStatus{{Name: "deps", Status: checker.StatusFailed}}
	cases := []struct {
		name   string
		fs     []finding.Finding
		st     []checker.CheckStatus
		failOn *finding.Severity
		strict bool
		want   int
	}{
		{"high at high", high, ok, sev(finding.High), false, 1},
		{"high at critical", high, ok, sev(finding.Critical), false, 0},
		{"high with --fail-on none", high, ok, nil, false, 0},
		{"high with --fail-on none and strict failed check", high, failed, nil, true, 2},
		{"failed not strict", nil, failed, nil, false, 0},
		{"failed not strict with finding", high, failed, sev(finding.High), false, 1},
		{"failed strict", nil, failed, nil, true, 2},
		{"finding beats failed check under strict", high, failed, sev(finding.High), true, 1},
		{"info only at low", info, ok, sev(finding.Low), false, 0},
		{"medium below high", []finding.Finding{{Severity: finding.Medium}}, ok, sev(finding.High), false, 0},
	}
	for _, c := range cases {
		if got := ExitCode(c.fs, c.st, c.failOn, c.strict); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func rulesAndFailingCheckers(t *testing.T) {
	t.Helper()
	old := defaultCheckers
	t.Cleanup(func() { defaultCheckers = old })
	defaultCheckers = func(data fs.FS, opt scanOptions) []checker.Checker {
		return []checker.Checker{rules.NewChecker(data), failing{}}
	}
}

func TestScanDefaultFailsOnHigh(t *testing.T) {
	useFakeDeps(t)
	if code, _, se := runCLI(t, "scan", sampleApp); code != 1 {
		t.Errorf("no options with a high finding: code=%d, want 1: %s", code, se)
	}
}

func TestScanFailOnNoneExitsZero(t *testing.T) {
	useFakeDeps(t)
	if code, _, se := runCLI(t, "scan", sampleApp, "--fail-on", "none"); code != 0 {
		t.Errorf("--fail-on none: code=%d, want 0: %s", code, se)
	}
}

func TestScanStrictFindingBeatsFailedCheck(t *testing.T) {
	rulesAndFailingCheckers(t)
	if code, _, se := runCLI(t, "scan", sampleApp, "--strict"); code != 1 {
		t.Errorf("high finding and failed check with --strict: code=%d, want 1: %s", code, se)
	}
}

func TestScanStrictFailedCheckOnly(t *testing.T) {
	rulesAndFailingCheckers(t)
	// --fail-on none leaves only the failed check, which --strict counts as 2.
	if code, _, se := runCLI(t, "scan", sampleApp, "--strict", "--fail-on", "none"); code != 2 {
		t.Errorf("failed check only with --strict: code=%d, want 2: %s", code, se)
	}
	if code, _, se := runCLI(t, "scan", sampleApp, "--fail-on", "none"); code != 0 {
		t.Errorf("failed check without --strict: code=%d, want 0: %s", code, se)
	}
}

func TestFailOnValues(t *testing.T) {
	for _, v := range []string{"critical", "high", "medium", "low"} {
		if s, err := ParseFailOn(v); err != nil || s == nil {
			t.Errorf("%s: %v %v", v, s, err)
		}
	}
	if s, err := ParseFailOn("none"); err != nil || s != nil {
		t.Errorf("none: %v %v", s, err)
	}
	for _, v := range []string{"info", "bogus", ""} {
		if _, err := ParseFailOn(v); err == nil || !strings.Contains(err.Error(), "none") {
			t.Errorf("%q: error should list none: %v", v, err)
		}
	}
	for name, text := range map[string]string{"scan": usageText, "watch": watchUsageText, "device": deviceUsageText} {
		if !strings.Contains(text, "|none]") {
			t.Errorf("%s usage lacks none", name)
		}
	}
}

// Every command that takes --fail-on follows one table: a finding at or
// above it is 1 and beats everything; otherwise something not read is 2;
// otherwise 0; with --fail-on none findings never count but 2 still does.
func TestExitCodeTableSameForAllCommands(t *testing.T) {
	high := []finding.Finding{{ID: "T-1", Severity: finding.High, Title: "t", Location: "x"}}
	low := []finding.Finding{{ID: "T-2", Severity: finding.Low, Title: "t", Location: "x"}}
	failedCheck := []checker.CheckStatus{{Name: "deps", Status: checker.StatusFailed}}
	cases := []struct {
		name   string
		fs     []finding.Finding
		unread bool
		failOn *finding.Severity
		want   int
	}{
		{"nothing", nil, false, sev(finding.High), 0},
		{"high at high", high, false, sev(finding.High), 1},
		{"low below high", low, false, sev(finding.High), 0},
		{"unread only", nil, true, sev(finding.High), 2},
		{"high beats unread", high, true, sev(finding.High), 1},
		{"low below high with unread", low, true, sev(finding.High), 2},
		{"none ignores high", high, false, nil, 0},
		{"none keeps unread as 2", high, true, nil, 2},
	}
	for _, c := range cases {
		var st []checker.CheckStatus
		var o watch.Outcome
		if c.unread {
			st = failedCheck
			o.Unverified = map[string]string{"k": "x"}
		}
		if got := ExitCode(c.fs, st, c.failOn, true); got != c.want {
			t.Errorf("scan --strict, %s: got %d want %d", c.name, got, c.want)
		}
		if got := watch.ExitCodeFor(o, c.fs, c.failOn); got != c.want {
			t.Errorf("watch, %s: got %d want %d", c.name, got, c.want)
		}
		run := deviceRun{home: t.TempDir(), formats: []string{"md"}, outDir: t.TempDir(), failOn: c.failOn}
		if got := deviceReport(run, c.fs, nil, c.unread, nil, io.Discard, io.Discard); got != c.want {
			t.Errorf("device, %s: got %d want %d", c.name, got, c.want)
		}
	}
}
