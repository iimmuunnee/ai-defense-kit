package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/report"
)

// devFake builds a value in memory so that no token- or key-shaped literal is
// written in this file.
func devFake(tag string) string { return tag + strings.Repeat("Xw4", 6) }
func devLongKey() string        { return "AK" + "IA" + strings.Repeat("R8", 8) }

func devWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// devPlant writes one stored token of every kind under home and returns the values.
func devPlant(t *testing.T, home string) []string {
	t.Helper()
	kube, kubeKey := devFake("kubetk"), base64.StdEncoding.EncodeToString([]byte(devFake("kubeky")))
	dock := base64.StdEncoding.EncodeToString([]byte("user:" + devFake("dockpw")))
	long, sec := devLongKey(), devFake("awssec")
	gh := devFake("ghtokn")
	devWrite(t, filepath.Join(home, ".kube", "config"), "users:\n- name: a\n  user:\n    token: "+kube+"\n- name: b\n  user:\n    client-key-data: "+kubeKey+"\n")
	devWrite(t, filepath.Join(home, ".docker", "config.json"), `{"auths": {"registry.example.test": {"auth": "`+dock+`"}}}`)
	devWrite(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = "+long+"\naws_secret_access_key = "+sec+"\n")
	devWrite(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: "+gh+"\n")
	return []string{kube, kubeKey, dock, long, sec, gh}
}

func devNoValue(t *testing.T, where, out string, values []string) {
	t.Helper()
	for _, v := range values {
		for i := 0; i+6 <= len(v); i++ {
			if piece := v[i : i+6]; strings.Contains(out, piece) {
				t.Errorf("%s holds a piece %q of a planted value", where, piece)
				break
			}
		}
	}
}

func devFindings(t *testing.T, out string) report.Report {
	t.Helper()
	var r report.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	return r
}

func TestDeviceFindsTokens(t *testing.T) {
	home := t.TempDir()
	devPlant(t, home)
	code, out, errs := runCLI(t, "device", "--home", home, "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	r := devFindings(t, out)
	if r.Kind != report.KindDevice {
		t.Errorf("kind = %q", r.Kind)
	}
	ids := map[string]int{}
	for _, f := range r.Findings {
		ids[f.ID]++
	}
	if ids["DV-001"] != 2 || ids["DV-002"] != 1 || ids["DV-003"] != 1 || ids["DV-004"] != 1 {
		t.Errorf("ids = %v", ids)
	}
}

func TestNeverPrintsValue(t *testing.T) {
	home := t.TempDir()
	values := devPlant(t, home)
	dir := t.TempDir()
	code, out, errs := runCLI(t, "device", "--home", home, "--format", "md,json,sarif", "--out", dir)
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	devNoValue(t, "stdout", out, values)
	devNoValue(t, "stderr", errs, values)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Errorf("want 3 reports and an evidence file, got %d", len(entries))
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		devNoValue(t, e.Name(), string(b), values)
		if strings.Contains(string(b), filepath.ToSlash(home)) || strings.Contains(string(b), home) {
			t.Errorf("%s holds the home folder path", e.Name())
		}
	}
	for _, f := range []string{"md", "json"} {
		code, out, errs := runCLI(t, "device", "--home", home, "--format", f)
		if code != 1 {
			t.Errorf("%s: code=%d", f, code)
		}
		devNoValue(t, f+" stdout", out, values)
		devNoValue(t, f+" stderr", errs, values)
	}
}

func TestDeviceMarkdown(t *testing.T) {
	home := t.TempDir()
	devPlant(t, home)
	_, out, _ := runCLI(t, "device", "--home", home)
	for _, want := range []string{"DV-001", "DV-004", "~/.kube/config", "user.token"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "스택:") || strings.Contains(out, "git 커밋") {
		t.Errorf("device report shows code-scan fields:\n%s", out)
	}
}

func TestDeviceNothingThere(t *testing.T) {
	home := t.TempDir()
	code, out, errs := runCLI(t, "device", "--home", home)
	if code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"~/.kube/config", "~/.docker/config.json", "~/.aws/credentials", "~/.config/gh/hosts.yml"} {
		if !strings.Contains(out, want) {
			t.Errorf("note lacks %s\n%s", want, out)
		}
	}
}

func TestDeviceFailOn(t *testing.T) {
	home := t.TempDir()
	devWrite(t, filepath.Join(home, ".docker", "config.json"), `{"auths": {"r.example.test": {"identitytoken": "`+devFake("id")+`"}}}`)
	if code, out, errs := runCLI(t, "device", "--home", home); code != 0 {
		t.Errorf("medium under default --fail-on high: code=%d\n%s\n%s", code, out, errs)
	}
	if code, _, _ := runCLI(t, "device", "--home", home, "--fail-on", "medium"); code != 1 {
		t.Errorf("--fail-on medium: code=%d", code)
	}
	if code, _, _ := runCLI(t, "device", "--home", home, "--fail-on", "info"); code != 2 {
		t.Errorf("--fail-on info: code=%d", code)
	}
}

func TestDeviceUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not deny reading on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home := t.TempDir()
	p := filepath.Join(home, ".kube", "config")
	devWrite(t, p, "users: []\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	code, out, errs := runCLI(t, "device", "--home", home)
	if code != 2 {
		t.Fatalf("unreadable alone: code=%d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "확인 못 함") || !strings.Contains(errs, "~/.kube/config") {
		t.Errorf("unreadable not shown:\n%s\n%s", out, errs)
	}
	// A finding at or above --fail-on wins over an unreadable file.
	devWrite(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: "+devFake("gh")+"\n")
	if code, _, _ := runCLI(t, "device", "--home", home); code != 1 {
		t.Errorf("finding and unreadable: code=%d", code)
	}
}

// A malformed file is not verified on every platform.
func TestDeviceMalformedIsExit2(t *testing.T) {
	home := t.TempDir()
	devWrite(t, filepath.Join(home, ".docker", "config.json"), "{")
	if code, out, errs := runCLI(t, "device", "--home", home); code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	// A finding at or above --fail-on wins over a file that was not verified.
	devWrite(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = "+devLongKey()+"\n")
	if code, out, errs := runCLI(t, "device", "--home", home); code != 1 {
		t.Fatalf("malformed and high: code=%d\n%s\n%s", code, out, errs)
	}
}

// A folder where a file belongs is not verified, on every platform.
func TestDeviceFolderIsExit2(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kube", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCLI(t, "device", "--home", home)
	if code != 2 || !strings.Contains(errs, "~/.kube/config") || !strings.Contains(out, "확인 못 함") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
}

// With --home, nothing from the real environment is read: every variable that
// moves a place points at a stored token, and none may be reported.
func TestDeviceHomeIgnoresRealEnv(t *testing.T) {
	decoy := t.TempDir()
	devPlant(t, decoy)
	kube := filepath.Join(decoy, "kubeconfig")
	devWrite(t, kube, "users:\n- user:\n    token: "+devFake("realenv")+"\n")
	creds := filepath.Join(decoy, "aws-credentials")
	devWrite(t, creds, "[default]\naws_access_key_id = "+devLongKey()+"\n")
	awsCfg := filepath.Join(decoy, "aws-config")
	devWrite(t, awsCfg, "[profile p]\naws_access_key_id = "+devLongKey()+"\n")
	ghDir := filepath.Join(decoy, "ghdir")
	devWrite(t, filepath.Join(ghDir, "hosts.yml"), "github.com:\n    oauth_token: "+devFake("ghdir")+"\n")
	devWrite(t, filepath.Join(decoy, "AppData", "GitHub CLI", "hosts.yml"), "github.com:\n    oauth_token: "+devFake("appdat")+"\n")

	t.Setenv("KUBECONFIG", kube)
	t.Setenv("DOCKER_CONFIG", filepath.Join(decoy, ".docker"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	t.Setenv("AWS_CONFIG_FILE", awsCfg)
	t.Setenv("AWS_ACCESS_KEY_ID", devLongKey())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(decoy, ".config"))
	t.Setenv("APPDATA", filepath.Join(decoy, "AppData"))
	// With GH_CONFIG_DIR set, then without it so XDG_CONFIG_HOME and APPDATA
	// would be the gh places.
	for _, ghConfigDir := range []string{ghDir, ""} {
		t.Setenv("GH_CONFIG_DIR", ghConfigDir)
		home := t.TempDir()
		code, out, errs := runCLI(t, "device", "--home", home, "--format", "json")
		if code != 0 || len(devFindings(t, out).Findings) != 0 {
			t.Fatalf("GH_CONFIG_DIR=%q: code=%d\n%s\n%s", ghConfigDir, code, out, errs)
		}
		if strings.Contains(out+errs, filepath.ToSlash(decoy)) || strings.Contains(out+errs, decoy) {
			t.Errorf("output names the decoy folder:\n%s\n%s", out, errs)
		}
	}
}

// The "nothing there" note is for a clean result only: a key found in the
// environment is not "nothing".
func TestDeviceNoteNotWithEnvFinding(t *testing.T) {
	old := deviceHomeEnv
	t.Cleanup(func() { deviceHomeEnv = old })
	deviceHomeEnv = func(k string) string {
		if k == "AWS_ACCESS_KEY_ID" {
			return devLongKey()
		}
		return ""
	}
	code, out, errs := runCLI(t, "device", "--home", t.TempDir())
	if code != 1 || !strings.Contains(out, "DV-003") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out+errs, "점검할 파일이 하나도 없습니다") {
		t.Errorf("nothing-there note beside a finding:\n%s\n%s", out, errs)
	}
}

// SARIF locations of a device report are not files of a repository, so they
// must not be tied to the source root.
func TestDeviceSARIFNotRepoRelative(t *testing.T) {
	home := t.TempDir()
	devPlant(t, home)
	code, out, errs := runCLI(t, "device", "--home", home, "--format", "sarif")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, "%SRCROOT%") {
		t.Errorf("device SARIF uses %%SRCROOT%%:\n%s", out)
	}
	if !strings.Contains(out, `"uri": "~/.kube/config"`) {
		t.Errorf("device SARIF lacks the location:\n%s", out)
	}
}

func TestDeviceArgs(t *testing.T) {
	cases := [][]string{
		{"device", "nosuch"},
		{"device", "--home", filepath.Join(t.TempDir(), "missing")},
		{"device", "--format", "xml"},
		{"device", "--bogus"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: code=%d", args, code)
		}
	}
	code, out, _ := runCLI(t, "device", "--help")
	if code != 0 || !strings.Contains(out, "--home") || !strings.Contains(out, "환경 변수") {
		t.Errorf("help: code=%d\n%s", code, out)
	}
	if !strings.Contains(usageText, "adk device") {
		t.Errorf("usage lacks device: %s", usageText)
	}
}
