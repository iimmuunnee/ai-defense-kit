package device

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

func TestPersistChange(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	rc := filepath.Join(home, ".zshrc")
	write(t, rc, "export EDITOR=vi\n")
	base := observe(t, o).Entries
	if _, ok := base["persist:~/.zshrc"]; !ok {
		t.Fatalf("~/.zshrc not observed: %v", base)
	}
	f, err := os.OpenFile(rc, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	const line = "echo planted-line-marker"
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 {
		t.Fatalf("findings = %+v", fs)
	}
	got := fs[0]
	if got.ID != "DV-103" || got.Severity != finding.Medium || got.Location != "persist:~/.zshrc" {
		t.Errorf("finding = %+v", got)
	}
	if !strings.Contains(got.Evidence, "~/.zshrc") || !strings.Contains(got.Evidence, "바뀜") {
		t.Errorf("evidence = %q", got.Evidence)
	}
	all := got.Evidence + got.Title + got.Location + got.Fingerprint
	if strings.Contains(all, "planted") || strings.Contains(all, "EDITOR") {
		t.Errorf("finding holds file content: %+v", got)
	}
	if got.ExplainKo == "" || got.Fix == "" {
		t.Errorf("explain or fix missing")
	}
}

func TestPersistNewLaunchAgent(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	write(t, filepath.Join(dir, "com.example.old.plist"), "<plist/>\n")
	write(t, filepath.Join(dir, "notes.txt"), "not a plist\n")
	base := observe(t, o).Entries
	if _, ok := base["persist:~/Library/LaunchAgents/notes.txt"]; ok {
		t.Errorf("a non-plist file is a launch point")
	}
	write(t, filepath.Join(dir, "com.example.new.plist"), "<plist/>\n")
	fs := Compare(base, observe(t, o), o)
	if len(fs) != 1 || fs[0].ID != "DV-103" || fs[0].Severity != finding.High ||
		fs[0].Location != "persist:~/Library/LaunchAgents/com.example.new.plist" || !strings.Contains(fs[0].Evidence, "추가") {
		t.Fatalf("findings = %+v", fs)
	}
	// Removed is a change too.
	base = observe(t, o).Entries
	if err := os.Remove(filepath.Join(dir, "com.example.old.plist")); err != nil {
		t.Fatal(err)
	}
	fs = Compare(base, observe(t, o), o)
	if len(fs) != 1 || fs[0].Severity != finding.High || !strings.Contains(fs[0].Evidence, "사라") {
		t.Fatalf("removed: %+v", fs)
	}
}

func TestPersistLinuxPoints(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	base := observe(t, o).Entries
	unit := filepath.Join(home, ".config", "systemd", "user", "job.service")
	write(t, unit, "[Service]\n")
	relink(t, filepath.Join("..", "job.service"), filepath.Join(home, ".config", "systemd", "user", "default.target.wants", "job.service"))
	write(t, filepath.Join(home, ".config", "autostart", "x.desktop"), "[Desktop Entry]\n")
	fs := Compare(base, observe(t, o), o)
	want := map[string]bool{
		"persist:~/.config/systemd/user/job.service":                      true,
		"persist:~/.config/systemd/user/default.target.wants/job.service": true,
		"persist:~/.config/autostart/x.desktop":                           true,
	}
	if len(fs) != len(want) {
		t.Fatalf("findings = %+v", fs)
	}
	for _, f := range fs {
		if !want[f.Location] || f.Severity != finding.High {
			t.Errorf("finding = %+v", f)
		}
	}
}

func TestPersistSystemPoints(t *testing.T) {
	skipWindows(t)
	home, root := t.TempDir(), t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil), SysRoot: root}
	write(t, filepath.Join(root, "etc", "crontab"), "# empty\n")
	base := observe(t, o).Entries
	if _, ok := base["persist:/etc/crontab"]; !ok {
		t.Fatalf("/etc/crontab not observed: %v", base)
	}
	write(t, filepath.Join(root, "etc", "cron.d", "job"), "* * * * * root true\n")
	write(t, filepath.Join(root, "Library", "LaunchDaemons", "com.example.d.plist"), "<plist/>\n")
	fs := Compare(base, observe(t, o), o)
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Location] = f.Severity == finding.High
	}
	if len(fs) != 2 || !got["persist:/etc/cron.d/job"] || !got["persist:/Library/LaunchDaemons/com.example.d.plist"] {
		t.Fatalf("findings = %+v", fs)
	}
	// Without a system root, only the home points are read.
	if s := observe(t, Options{Home: home, Getenv: envOf(nil)}); len(s.Entries) != 0 {
		t.Errorf("system points read without SysRoot: %v", s.Entries)
	}
}

func TestPersistUnreadable(t *testing.T) {
	skipWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	rc := filepath.Join(home, ".bashrc")
	write(t, rc, "true\n")
	dir := filepath.Join(home, "Library", "LaunchAgents")
	write(t, filepath.Join(dir, "a.plist"), "<plist/>\n")
	base := observe(t, o).Entries
	for _, p := range []string{rc, dir} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o700) })
	}
	snap := observe(t, o)
	if _, ok := snap.Unread["persist:~/.bashrc"]; !ok {
		t.Errorf("unread = %v", snap.Unread)
	}
	if _, ok := snap.Unread["persist:~/Library/LaunchAgents/"]; !ok {
		t.Errorf("unread = %v", snap.Unread)
	}
	// What was not read is neither changed nor removed.
	if fs := Compare(base, snap, o); len(fs) != 0 {
		t.Errorf("findings = %+v", fs)
	}
}

func TestUserCrontab(t *testing.T) {
	old := runCrontab
	t.Cleanup(func() { runCrontab = old })
	const secretish = "planted-cron-line"
	cases := []struct {
		name          string
		out, errOut   string
		err           error
		entry, unread bool
	}{
		{name: "none", errOut: "no crontab for someone\n", err: errors.New("exit status 1"), entry: false},
		{name: "some", out: "* * * * * " + secretish + "\n", entry: true},
		{name: "empty", out: "", entry: false},
		{name: "fails", errOut: secretish, err: errors.New("exit status 2 " + secretish), entry: true, unread: true},
	}
	for _, c := range cases {
		runCrontab = func(context.Context) ([]byte, []byte, error) { return []byte(c.out), []byte(c.errOut), c.err }
		snap := Observe(context.Background(), Options{Home: t.TempDir(), Getenv: envOf(nil), Crontab: UserCrontab})
		_, hasEntry := snap.Entries[CrontabKey]
		why, hasUnread := snap.Unread[CrontabKey]
		if hasEntry != c.entry || hasUnread != c.unread {
			t.Errorf("%s: entries=%v unread=%v", c.name, snap.Entries, snap.Unread)
		}
		for k, v := range snap.Entries[CrontabKey] {
			if strings.Contains(k+v, secretish) {
				t.Errorf("%s: observation holds the crontab", c.name)
			}
		}
		if strings.Contains(why, secretish) {
			t.Errorf("%s: reason holds the output: %q", c.name, why)
		}
	}
}

// No crontab command where the baseline has a user crontab: not verified, not removed.
func TestCrontabCommandMissing(t *testing.T) {
	old := runCrontab
	t.Cleanup(func() { runCrontab = old })
	runCrontab = func(context.Context) ([]byte, []byte, error) { return nil, nil, errNoCrontabCmd }
	o := Options{Home: t.TempDir(), Getenv: envOf(nil), Crontab: UserCrontab}
	snap := Observe(context.Background(), o)
	if len(snap.Entries) != 0 || len(snap.Unread) != 0 {
		t.Fatalf("entries=%v unread=%v", snap.Entries, snap.Unread)
	}
	// Not in the baseline either: nothing to say.
	Reconcile(&snap, map[string]watch.Observation{})
	if len(snap.Unread) != 0 {
		t.Errorf("unread without a baselined crontab: %v", snap.Unread)
	}
	base := map[string]watch.Observation{CrontabKey: {"point": "cron", "sha256": strings.Repeat("a", 64)}}
	Reconcile(&snap, base)
	if _, ok := snap.Unread[CrontabKey]; !ok {
		t.Errorf("unread = %v", snap.Unread)
	}
	if fs := Compare(base, snap, o); len(fs) != 0 {
		t.Errorf("findings = %+v", fs)
	}
}

// A masked systemd unit is a link to /dev/null: it is recorded as such, not
// opened and not left unverified.
func TestPersistLinkToDevNull(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	unit := filepath.Join(home, ".config", "systemd", "user", "pulseaudio.socket")
	relink(t, "/dev/null", unit)
	snap := observe(t, o)
	obs, ok := snap.Entries["persist:~/.config/systemd/user/pulseaudio.socket"]
	if !ok || obs["link"] != "/dev/null" || obs["sha256"] != "" || obs["state"] != stateNotRegular || len(snap.Unread) != 0 {
		t.Fatalf("entries=%v unread=%v", snap.Entries, snap.Unread)
	}
	if fs := Compare(snap.Entries, observe(t, o), o); len(fs) != 0 {
		t.Errorf("unchanged mask: %+v", fs)
	}
	// Unmasked into a real unit: a change.
	_ = os.Remove(unit)
	write(t, unit, "[Unit]\n")
	if fs := Compare(snap.Entries, observe(t, o), o); len(fs) != 1 || ids(fs)["DV-103/high"] != 1 {
		t.Errorf("unmasked: %+v", fs)
	}
}

// What cannot be read is recorded as unreadable: still unreadable is not
// verified, readable later is a change.
func TestPersistUnreadableRecorded(t *testing.T) {
	skipWindows(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	rc := filepath.Join(home, ".bashrc")
	write(t, rc, "true\n")
	dir := filepath.Join(home, ".config", "autostart")
	write(t, filepath.Join(dir, "a.desktop"), "[Desktop Entry]\n")
	for _, p := range []string{rc, dir} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o700) })
	}
	snap := observe(t, o)
	for _, k := range []string{"persist:~/.bashrc", "persist:~/.config/autostart/"} {
		if snap.Entries[k]["state"] != stateUnreadable {
			t.Errorf("%s: entries=%v", k, snap.Entries)
		}
		if _, ok := snap.Unread[k]; !ok {
			t.Errorf("%s: unread=%v", k, snap.Unread)
		}
	}
	base := snap.Entries
	if fs := Compare(base, observe(t, o), o); len(fs) != 0 {
		t.Errorf("still unreadable: %+v", fs)
	}
	for _, p := range []string{rc, dir} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fs := Compare(base, observe(t, o), o)
	got := map[string]string{}
	for _, f := range fs {
		got[f.Location] = f.Evidence
	}
	if len(fs) != 2 || !strings.Contains(got["persist:~/.bashrc"], "읽지 못함") || got["persist:~/.config/autostart/a.desktop"] == "" {
		t.Errorf("readable again: %+v", fs)
	}
}

// Login shells read .zlogin (macOS Terminal opens one) and .bash_login.
func TestPersistLoginShellFiles(t *testing.T) {
	skipWindows(t)
	home := t.TempDir()
	o := Options{Home: home, Getenv: envOf(nil)}
	base := observe(t, o).Entries
	write(t, filepath.Join(home, ".zlogin"), "true\n")
	write(t, filepath.Join(home, ".bash_login"), "true\n")
	fs := Compare(base, observe(t, o), o)
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Location] = f.Severity == finding.Medium
	}
	if len(fs) != 2 || !got["persist:~/.zlogin"] || !got["persist:~/.bash_login"] {
		t.Errorf("findings = %+v", fs)
	}
}
