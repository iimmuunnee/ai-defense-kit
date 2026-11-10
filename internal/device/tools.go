package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// ToolNames are the developer tools whose entry files are compared with the
// baseline, in the order they are looked up.
var ToolNames = []string{"pyenv", "brew", "python", "python3", "node", "npm", "git", "docker", "kubectl", "aws", "gh"}

// ToolPrefix and PersistPrefix start every baseline key of this package.
const (
	ToolPrefix    = "tool:"
	PersistPrefix = "persist:"
)

// maxToolSize bounds the file hashed for one tool. Tool binaries can be large
// (node is over 100 MiB); a larger one is reported as not verified.
const maxToolSize = 256 << 20

// maxHops is how many symbolic links in a row the kernel follows: 32 on
// macOS (MAXSYMLINKS), 40 on Linux. Past it the shell cannot run the tool
// either, so it is not there.
var maxHops = hopLimit(runtime.GOOS)

func hopLimit(goos string) int {
	if goos == "darwin" {
		return 32
	}
	return 40
}

// Options says what Observe looks at. Nothing outside it is read.
type Options struct {
	Home string
	// Path is the PATH list the tools are looked up in.
	Path string
	// Getenv supplies HOMEBREW_PREFIX, PYENV_ROOT, NVM_DIR and FNM_DIR.
	Getenv func(string) string
	// SysRoot is where the system-wide persistence points are read from ("/"
	// on a real run). Empty: they are not read.
	SysRoot string
	// Crontab reads the user crontab. Nil: it is not read.
	Crontab func(context.Context) (data []byte, present bool, err error)
}

func (o Options) env(k string) string {
	if o.Getenv == nil {
		return ""
	}
	return o.Getenv(k)
}

// PathKey is the baseline key of the PATH the tools were looked up in. A
// later check uses the same PATH, so a scheduled run with a short PATH, or
// another shell of a version manager, does not see the tools as moved.
const PathKey = "env:PATH"

// PathEntry records a PATH list, its folders under home as "~/...".
func PathEntry(home, path string) watch.Observation {
	dirs := filepath.SplitList(path)
	for i, d := range dirs {
		if filepath.IsAbs(d) {
			dirs[i] = Display(home, filepath.Clean(d))
		}
	}
	return watch.Observation{"dirs": strings.Join(dirs, "\n")}
}

// PathOf is the PATH list an entry recorded.
func PathOf(home string, obs watch.Observation) string {
	if obs["dirs"] == "" {
		return ""
	}
	dirs := strings.Split(obs["dirs"], "\n")
	for i, d := range dirs {
		switch {
		case d == "~":
			dirs[i] = home
		case strings.HasPrefix(d, "~/"):
			dirs[i] = filepath.Join(home, filepath.FromSlash(d[2:]))
		}
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}

// show displays a path that folder links have been resolved in: under the
// home folder, resolved or not, it starts with "~/".
func (o Options) show(p string) string {
	if rh, err := filepath.EvalSymlinks(o.Home); err == nil && within(p, rh) {
		return Display(rh, p)
	}
	return Display(o.Home, p)
}

// Snapshot is what one Observe saw.
type Snapshot struct {
	// Entries are keyed "tool:<name>" and "persist:<path>". A missing tool or
	// file has no entry.
	Entries map[string]watch.Observation
	// Unread holds what exists but could not be read: key -> why. A key that
	// ends in "/" is a folder: nothing under it was read.
	Unread map[string]string
	// CrontabMissing: there is no /usr/bin/crontab, so the user crontab was
	// not read. Reconcile turns it into Unread when the baseline has one.
	CrontabMissing bool
}

// Observe reads the tools and the persistence points. It never runs a tool.
func Observe(ctx context.Context, o Options) Snapshot {
	s := Snapshot{Entries: map[string]watch.Observation{}, Unread: map[string]string{}}
	observeTools(o, &s)
	observePersist(ctx, o, &s)
	return s
}

// Reconcile marks what this snapshot could not see that the baseline holds:
// a user crontab with no crontab command to read it is not verified, not removed.
func Reconcile(s *Snapshot, base map[string]watch.Observation) {
	if _, ok := base[CrontabKey]; ok && s.CrontabMissing {
		if s.Unread == nil {
			s.Unread = map[string]string{}
		}
		s.Unread[CrontabKey] = "crontab 명령(/usr/bin/crontab)이 없어 사용자 크론을 읽지 못했습니다"
	}
}

func observeTools(o Options, s *Snapshot) {
	var dirs []string
	for _, d := range filepath.SplitList(o.Path) {
		// A relative entry depends on the folder adk runs in; it is skipped.
		if filepath.IsAbs(d) {
			dirs = append(dirs, filepath.Clean(d))
		}
	}
	for _, name := range ToolNames {
		key := ToolPrefix + name
		entry := lookPath(dirs, name)
		if entry == "" {
			continue
		}
		chain, final, err := linkChain(entry)
		if err == nil {
			var real string
			if real, err = filepath.EvalSymlinks(entry); err != nil {
				err = errors.New("링크를 따라가지 못했습니다")
			} else {
				var sum string
				if sum, err = hashFile(entry); err == nil {
					s.Entries[key] = toolObservation(o, entry, final, real, sum, chain)
				}
			}
		}
		if err != nil {
			s.Entries[key] = watch.Observation{"entry": Display(o.Home, entry), "state": stateUnreadable}
			s.Unread[key] = Display(o.Home, entry) + ": " + err.Error()
		}
	}
}

func toolObservation(o Options, entry, final, real, sum string, chain []string) watch.Observation {
	obs := watch.Observation{
		"entry":  Display(o.Home, entry),
		"kind":   "file",
		"target": Display(o.Home, final),
		"real":   o.show(real),
		"sha256": sum,
	}
	if len(chain) > 0 {
		obs["kind"] = "link"
		shown := make([]string, len(chain))
		for i, c := range chain {
			shown[i] = Display(o.Home, c)
		}
		obs["chain"] = strings.Join(shown, "\n")
		if outsideBrew(o, entry, real) {
			obs["outside"] = "homebrew"
		}
	}
	return obs
}

// lookPath returns the first executable regular file named name in dirs, as a
// shell would run it, or "".
func lookPath(dirs []string, name string) string {
	for _, d := range dirs {
		p := filepath.Join(d, name)
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// linkChain follows the symbolic links from entry: each hop, then the file
// at the end, as the link texts say. Folders on the way are not resolved
// here; the real path is taken separately for every inside/outside decision.
func linkChain(entry string) ([]string, string, error) {
	var chain []string
	cur := entry
	for {
		st, err := os.Lstat(cur)
		if err != nil {
			return nil, "", errors.New("링크를 따라가지 못했습니다")
		}
		if st.Mode()&fs.ModeSymlink == 0 {
			return chain, cur, nil
		}
		if len(chain) == maxHops {
			return nil, "", errors.New("링크가 너무 많이 이어집니다")
		}
		t, err := os.Readlink(cur)
		if err != nil {
			return nil, "", errors.New("링크를 읽지 못했습니다")
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(cur), t)
		}
		cur = filepath.Clean(t)
		chain = append(chain, cur)
	}
}

// hashFile returns the SHA-256 of what running path executes: the file at
// the end of its links, opened the way the kernel opens it.
func hashFile(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", openError(err)
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("일반 파일이 아니어서 읽지 않았습니다")
	}
	f, err := openRead(path)
	if err != nil {
		return "", openError(err)
	}
	defer f.Close()
	if st, err = f.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", errors.New("일반 파일이 아니어서 읽지 않았습니다")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxToolSize+1))
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return "", errors.New("읽을 권한이 없습니다")
		}
		return "", errors.New("파일을 읽지 못했습니다")
	}
	if n > maxToolSize {
		return "", fmt.Errorf("파일이 %dMiB보다 커서 해시를 계산하지 않았습니다", maxToolSize>>20)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// brewPrefixes are the places Homebrew installs into.
func brewPrefixes(o Options) []string {
	out := []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"}
	if p := o.env("HOMEBREW_PREFIX"); p != "" && filepath.IsAbs(p) {
		out = append(out, filepath.Clean(p))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// isBrewPrefix: Homebrew is installed at p, not merely a folder of that name.
func isBrewPrefix(p string) bool {
	if st, err := os.Stat(filepath.Join(p, "Cellar")); err == nil && st.IsDir() {
		return true
	}
	_, err := os.Stat(filepath.Join(p, "bin", "brew"))
	return err == nil
}

// realRoot resolves the folders above root but not root itself: a root that
// is itself a link elsewhere then holds nothing, rather than that elsewhere.
func realRoot(root string) string {
	if parent, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		return filepath.Join(parent, filepath.Base(root))
	}
	return filepath.Clean(root)
}

// brewOwned are the folders under a Homebrew prefix that its own links point
// into: formulas (Cellar, opt), casks (Caskroom), brew itself (Homebrew) and
// the npm that Homebrew's node installs (lib/node_modules).
var brewOwned = []string{"Cellar", "opt", "Caskroom", "Homebrew", filepath.Join("lib", "node_modules")}

// within reports whether path is inside dir.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// inAppBundle: a cask's binary link points into its app in /Applications.
func inAppBundle(path string) bool {
	segs := strings.Split(filepath.ToSlash(path), "/")
	return len(segs) > 3 && segs[0] == "" && segs[1] == "Applications" && strings.HasSuffix(segs[2], ".app")
}

// outsideBrew is the DV-102 condition: an entry in a Homebrew bin whose real
// file, every folder link resolved, is outside what Homebrew manages.
func outsideBrew(o Options, entry, real string) bool {
	for _, p := range brewPrefixes(o) {
		if filepath.Dir(entry) != filepath.Join(p, "bin") || !isBrewPrefix(p) {
			continue
		}
		for _, sub := range brewOwned {
			if within(real, realRoot(filepath.Join(p, sub))) {
				return false
			}
		}
		return !inAppBundle(real)
	}
	return false
}

// InitFindings are what init lists: each link already outside the Homebrew
// tree is a medium review item, recorded in the baseline with the rest. Only
// one that is new or changed later is high.
func InitFindings(s Snapshot, o Options) []finding.Finding {
	var out []finding.Finding
	for _, k := range slices.Sorted(maps.Keys(s.Entries)) {
		obs := s.Entries[k]
		if !strings.HasPrefix(k, ToolPrefix) || obs["outside"] == "" {
			continue
		}
		ev := obs["entry"] + " -> " + obs["real"] + " (Homebrew가 관리하는 폴더 밖, 기준값에 기록함)"
		out = append(out, newChangeFinding("DV-102", finding.Medium, k, ev, titles["DV-102"]+"(검토 항목)", "init\x00"+obs["real"]+"\x00"+obs["sha256"]))
	}
	return out
}

// toolChange words a change of one tool, or says it is an upgrade.
func toolChange(key string, old, now watch.Observation, inBase, inNow bool, roots upgradeRoots) (f finding.Finding, upgrade, changed bool) {
	if inBase && inNow {
		old, now = sameShell(old), sameShell(now)
		if len(watch.Diff(key, old, now)) == 0 {
			return finding.Finding{}, false, false
		}
	}
	// A link outside the Homebrew tree that is new or changed is DV-102, in
	// place of DV-101: the same tool is not reported twice.
	if inNow && now["outside"] != "" {
		ev := "새로 생김: " + now["entry"] + " -> " + now["real"] + " (Homebrew가 관리하는 폴더 밖)"
		if inBase {
			ev = "기준값과 다름: " + now["entry"] + " -> " + now["real"] + " (Homebrew가 관리하는 폴더 밖); " + strings.Join(changedParts(old, now), "; ")
		}
		return newChangeFinding("DV-102", finding.High, key, ev, titles["DV-102"], now["real"]+"\x00"+now["sha256"]), false, true
	}
	switch {
	case !inBase:
		return newChangeFinding("DV-101", finding.High, key, "새로 생김: "+now["entry"], titles["DV-101"], "added\x00"+now["sha256"]), false, true
	case !inNow:
		return newChangeFinding("DV-101", finding.High, key, "사라짐: 기준값에는 "+old["entry"], titles["DV-101"], "removed"), false, true
	}
	if upgradeShaped(old, now, roots) {
		return finding.Finding{}, true, true
	}
	return newChangeFinding("DV-101", finding.High, key, strings.Join(changedParts(old, now), "; "), titles["DV-101"], now["real"]+"\x00"+now["sha256"]), false, true
}

// changedHop words the first link hop that differs.
func changedHop(old, now watch.Observation) string {
	oc, nc := strings.Split(old["chain"], "\n"), strings.Split(now["chain"], "\n")
	for i := range max(len(oc), len(nc)) {
		a, b := "(없음)", "(없음)"
		if i < len(oc) && oc[i] != "" {
			a = oc[i]
		}
		if i < len(nc) && nc[i] != "" {
			b = nc[i]
		}
		if a != b {
			return a + " -> " + b
		}
	}
	return ""
}

// changedParts words what differs between two observations of one tool.
func changedParts(old, now watch.Observation) []string {
	var parts []string
	if old["entry"] != now["entry"] {
		parts = append(parts, "진입 경로: "+old["entry"]+" -> "+now["entry"])
	}
	if old["state"] == stateUnreadable {
		return append(parts, "기준값을 만들 때 읽지 못했던 실행 파일을 이제 읽음: "+now["real"])
	}
	isLink := old["kind"] == "link" || now["kind"] == "link"
	switch {
	case isLink && old["target"] != now["target"]:
		parts = append(parts, "링크 대상: "+old["target"]+" -> "+now["target"])
	case isLink && old["chain"] != now["chain"]:
		parts = append(parts, "링크 단계: "+changedHop(old, now))
	}
	if old["real"] != now["real"] && old["target"] == now["target"] {
		parts = append(parts, "실제 파일 위치: "+old["real"]+" -> "+now["real"])
	}
	if old["kind"] != now["kind"] {
		parts = append(parts, "종류: "+old["kind"]+" -> "+now["kind"])
	}
	if old["sha256"] != now["sha256"] {
		parts = append(parts, "내용(SHA-256)이 다름: "+now["real"])
	}
	if old["outside"] != now["outside"] {
		parts = append(parts, "Homebrew 밖을 가리키던 링크가 안쪽으로 바뀜")
	}
	if len(parts) == 0 {
		parts = append(parts, "기준값과 다름")
	}
	return parts
}

// Skipped: k was not read this time, so it is neither changed nor removed.
func Skipped(k string, unread map[string]string) bool {
	if _, ok := unread[k]; ok {
		return true
	}
	for u := range unread {
		if strings.HasSuffix(u, "/") && strings.HasPrefix(k, u) {
			return true
		}
	}
	return false
}

// Compare returns the findings of cur against the baseline entries: DV-101
// for tools, DV-102 for links outside the Homebrew tree that are new or
// changed, DV-103 for persistence points. Tools that look officially upgraded
// are one medium DV-101 together, with the pyenv shims rewritten beside an
// upgrade of pyenv.
func Compare(base map[string]watch.Observation, cur Snapshot, o Options) []finding.Finding {
	keySet := map[string]bool{}
	for k := range base {
		keySet[k] = true
	}
	for k := range cur.Entries {
		keySet[k] = true
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	roots := rootsOf(o)
	var out, shimFindings []finding.Finding
	var upgraded, shims []string
	for _, k := range keys {
		if Skipped(k, cur.Unread) {
			continue
		}
		old, inBase := base[k]
		now, inNow := cur.Entries[k]
		switch {
		case strings.HasPrefix(k, ToolPrefix):
			f, up, changed := toolChange(k, old, now, inBase, inNow, roots)
			switch {
			case up:
				upgraded = append(upgraded, k)
			case changed && inBase && inNow && shimRewrite(old, now, roots):
				shims = append(shims, k)
				shimFindings = append(shimFindings, f)
			case changed:
				out = append(out, f)
			}
		case strings.HasPrefix(k, PersistPrefix):
			if f, ok := persistChange(k, old, now, inBase, inNow); ok {
				out = append(out, f)
			}
		}
	}
	if slices.Contains(upgraded, ToolPrefix+"pyenv") {
		upgraded = append(upgraded, shims...)
	} else {
		out = append(out, shimFindings...)
	}
	if len(upgraded) > 0 {
		out = append(out, upgradeFinding(upgraded, base, cur.Entries))
	}
	return out
}

func newChangeFinding(id string, sev finding.Severity, location, evidence, title, sig string) finding.Finding {
	return finding.Finding{
		ID:          id,
		Kind:        id,
		Source:      Source,
		Severity:    sev,
		Confidence:  finding.Certain,
		Location:    location,
		Evidence:    evidence,
		Title:       title,
		ExplainKo:   readText("explain/" + id + ".md"),
		Fix:         readText("fixes/" + id + "/device.md"),
		Fingerprint: finding.MakeFingerprint(id, location, sig),
	}
}
