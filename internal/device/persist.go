package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// Kinds of persistence point, as the "point" field of an observation.
const (
	pointLaunch    = "launch"
	pointSystemd   = "systemd"
	pointAutostart = "autostart"
	pointCron      = "cron"
	pointShell     = "shell"
)

var pointLabels = map[string]string{
	pointLaunch:    "LaunchAgents·LaunchDaemons",
	pointSystemd:   "systemd 사용자 서비스",
	pointAutostart: "데스크톱 자동 시작",
	pointCron:      "크론",
	pointShell:     "셸 시작 파일",
}

// CrontabKey is the key of the user crontab, read with `crontab -l`.
const CrontabKey = PersistPrefix + "crontab -l"

// persistFile is one file that runs something when the user logs in, opens a
// shell or on a schedule. sys: under Options.SysRoot, otherwise under home.
type persistFile struct {
	rel   string
	sys   bool
	point string
}

// persistDir is a folder whose files are such points. ext limits them by
// name; sub also reads one level of folders (systemd's *.wants, *.d).
type persistDir struct {
	rel   string
	sys   bool
	point string
	ext   string
	sub   bool
}

var persistFiles = []persistFile{
	{".zshrc", false, pointShell},
	{".zprofile", false, pointShell},
	{".zshenv", false, pointShell},
	{".zlogin", false, pointShell},
	{".bashrc", false, pointShell},
	{".bash_profile", false, pointShell},
	{".bash_login", false, pointShell},
	{".profile", false, pointShell},
	{".config/fish/config.fish", false, pointShell},
	{"etc/crontab", true, pointCron},
}

var persistDirs = []persistDir{
	{"Library/LaunchAgents", false, pointLaunch, ".plist", false},
	{".config/systemd/user", false, pointSystemd, "", true},
	{".config/autostart", false, pointAutostart, ".desktop", false},
	{"Library/LaunchAgents", true, pointLaunch, ".plist", false},
	{"Library/LaunchDaemons", true, pointLaunch, ".plist", false},
	{"etc/cron.d", true, pointCron, "", false},
}

// place returns where rel is and how it is shown: "~/..." under home, the
// absolute path under the system root.
func (o Options) place(rel string, sys bool) (string, string) {
	if sys {
		return filepath.Join(o.SysRoot, filepath.FromSlash(rel)), "/" + rel
	}
	p := filepath.Join(o.Home, filepath.FromSlash(rel))
	return p, Display(o.Home, p)
}

func observePersist(ctx context.Context, o Options, s *Snapshot) {
	for _, f := range persistFiles {
		if f.sys && o.SysRoot == "" {
			continue
		}
		p, shown := o.place(f.rel, f.sys)
		observePoint(o, s, p, shown, f.point)
	}
	for _, d := range persistDirs {
		if d.sys && o.SysRoot == "" {
			continue
		}
		p, shown := o.place(d.rel, d.sys)
		observePointDir(o, s, p, shown, d.point, d.ext, d.sub)
	}
	if o.Crontab != nil {
		data, present, err := o.Crontab(ctx)
		switch {
		case errors.Is(err, errNoCrontabCmd):
			s.CrontabMissing = true
		case err != nil:
			unreadPoint(s, CrontabKey, watch.Observation{"point": pointCron}, err.Error())
		case present:
			sum := sha256.Sum256(data)
			s.Entries[CrontabKey] = watch.Observation{"point": pointCron, "sha256": hex.EncodeToString(sum[:])}
		}
	}
}

// States of a persistence point or tool that was not hashed, as the "state"
// field of its observation. A point is recorded in the baseline in whatever
// state it is, so that one that cannot be read does not stop init.
const (
	// stateUnreadable: it is there but could not be read. The key is also in
	// Snapshot.Unread, so the run is not verified.
	stateUnreadable = "unreadable"
	// stateNotRegular: not a regular file (a link to /dev/null, as a masked
	// systemd unit is, a FIFO, a folder). It is not opened.
	stateNotRegular = "not-regular"
	// stateNotFolder: a file where a folder of points is looked for.
	stateNotFolder = "not-folder"
)

var stateLabels = map[string]string{
	"":              "일반 파일",
	stateUnreadable: "읽지 못함",
	stateNotRegular: "일반 파일 아님",
	stateNotFolder:  "폴더 아님",
}

// unreadPoint records a point that is there but could not be read.
func unreadPoint(s *Snapshot, key string, obs watch.Observation, why string) {
	obs["state"] = stateUnreadable
	s.Entries[key] = obs
	s.Unread[key] = why
}

func observePointDir(o Options, s *Snapshot, dir, shown, point, ext string, sub bool) {
	key := PersistPrefix + shown + "/"
	st, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		unreadPoint(s, key, watch.Observation{"point": point}, openError(err).Error())
		return
	}
	if !st.IsDir() {
		s.Entries[key] = watch.Observation{"point": point, "state": stateNotFolder}
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		unreadPoint(s, key, watch.Observation{"point": point}, "폴더를 읽지 못했습니다")
		return
	}
	for _, e := range entries {
		p, name := filepath.Join(dir, e.Name()), shown+"/"+e.Name()
		if e.IsDir() {
			if sub {
				observePointDir(o, s, p, name, point, ext, false)
			}
			continue
		}
		if ext != "" && !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		observePoint(o, s, p, name, point)
	}
}

// observePoint records one file: where its link points, if it is one, and
// the SHA-256 of what it holds. Never the content. What is not a regular
// file is recorded as such and not opened.
func observePoint(o Options, s *Snapshot, path, shown, point string) {
	key := PersistPrefix + shown
	lst, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	obs := watch.Observation{"point": point}
	if err != nil {
		unreadPoint(s, key, obs, openError(err).Error())
		return
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		t, err := os.Readlink(path)
		if err != nil {
			unreadPoint(s, key, obs, "링크를 읽지 못했습니다")
			return
		}
		if filepath.IsAbs(t) {
			obs["link"] = Display(o.Home, t)
		} else {
			obs["link"] = filepath.ToSlash(t)
		}
	}
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// A link to nothing: the link itself is the point.
		s.Entries[key] = obs
		return
	case err != nil:
		unreadPoint(s, key, obs, openError(err).Error())
		return
	case !st.Mode().IsRegular():
		obs["state"] = stateNotRegular
		s.Entries[key] = obs
		return
	}
	b, err := readFile(path)
	if err != nil {
		unreadPoint(s, key, obs, err.Error())
		return
	}
	sum := sha256.Sum256(b)
	obs["sha256"] = hex.EncodeToString(sum[:])
	s.Entries[key] = obs
}

// persistChange words a change of one persistence point. The evidence names
// the file and what happened to it, never what it holds.
func persistChange(key string, old, now watch.Observation, inBase, inNow bool) (finding.Finding, bool) {
	shown := strings.TrimPrefix(key, PersistPrefix)
	var what, sig string
	point := now["point"]
	switch {
	case !inBase && inNow:
		what, sig = "추가됨: "+shown, "added\x00"+now["sha256"]+"\x00"+now["link"]
	case inBase && !inNow:
		if strings.HasSuffix(key, "/") {
			// A folder recorded as unreadable or as a file that is now a
			// readable folder: the points in it are reported one by one.
			return finding.Finding{}, false
		}
		what, sig, point = "사라짐: "+shown, "removed", old["point"]
	default:
		if len(watch.Diff(key, old, now)) == 0 {
			return finding.Finding{}, false
		}
		what, sig = "바뀜: "+shown+" (내용은 적지 않습니다)", now["sha256"]+"\x00"+now["link"]+"\x00"+now["state"]
		switch {
		case old["state"] != now["state"]:
			what = "바뀜: " + shown + " (상태: " + stateLabels[old["state"]] + " -> " + stateLabels[now["state"]] + ")"
		case old["link"] != now["link"]:
			what = "바뀜: " + shown + " (링크 대상이 다름)"
		}
	}
	if !inBase && now["state"] != "" {
		what += " (" + stateLabels[now["state"]] + ")"
	}
	sev := finding.High
	if point == pointShell {
		sev = finding.Medium
	}
	title := titles["DV-103"]
	if l := pointLabels[point]; l != "" {
		title += " (" + l + ")"
	}
	return newChangeFinding("DV-103", sev, key, what, title, sig), true
}

// crontabPath is run by its absolute path, never looked up in PATH.
const crontabPath = "/usr/bin/crontab"

// crontabTimeout bounds `crontab -l`, which reads a local file.
const crontabTimeout = 10 * time.Second

var errNoCrontabCmd = errors.New("crontab 명령이 없습니다")

// cappedBuffer keeps at most max bytes and remembers whether there was more.
type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// runCrontab runs `/usr/bin/crontab -l`. Tests replace it.
var runCrontab = func(ctx context.Context) ([]byte, []byte, error) {
	if _, err := os.Stat(crontabPath); err != nil {
		return nil, nil, errNoCrontabCmd
	}
	ctx, cancel := context.WithTimeout(ctx, crontabTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, crontabPath, "-l")
	out, errOut := &cappedBuffer{max: maxFileSize}, &cappedBuffer{max: 4096}
	cmd.Stdout, cmd.Stderr = out, errOut
	// A child that kept the pipes open must not hold Wait after the kill.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err == nil && out.over {
		err = errors.New("too large")
	}
	return out.buf.Bytes(), errOut.buf.Bytes(), err
}

// UserCrontab reads the user crontab. No crontab is not present; no crontab
// command is errNoCrontabCmd, which the caller weighs against the baseline.
// A failure is a fixed sentence: the output is never passed on.
func UserCrontab(ctx context.Context) ([]byte, bool, error) {
	out, errOut, err := runCrontab(ctx)
	switch {
	case errors.Is(err, errNoCrontabCmd):
		return nil, false, errNoCrontabCmd
	case err != nil:
		if strings.Contains(strings.ToLower(string(errOut)), "no crontab for") {
			return nil, false, nil
		}
		return nil, false, errors.New("crontab -l을 실행하지 못했습니다")
	case len(bytes.TrimSpace(out)) == 0:
		return nil, false, nil
	}
	return out, true, nil
}
