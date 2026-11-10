package device

import (
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// Version folder names that an official upgrade makes, kept tight so that a
// folder merely named like a version is not one: Homebrew's version with an
// optional _N revision; pyenv's CPython names with its free-threaded (t),
// pre-release (a1, b1, c1, rc1) and -dev tags; nvm's and fnm's node versions,
// three numbers with a leading v.
var (
	cellarVersion = regexp.MustCompile(`^\d+(\.\d+)*(_\d+)?$`)
	pyenvVersion  = regexp.MustCompile(`^\d+(\.\d+)*(t|[abc]\d+|rc\d+|-dev)?$`)
	nodeVersion   = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)
)

// versionOnly reports whether a and b, slash paths, differ only in segments
// that both match version.
func versionOnly(a, b string, version *regexp.Regexp) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] && (!version.MatchString(as[i]) || !version.MatchString(bs[i])) {
			return false
		}
	}
	return true
}

// versionRoot is where an official upgrade puts a new version.
type versionRoot struct {
	shown, real string // as the link text says, and with folder links resolved
	version     *regexp.Regexp
}

// upgradeRoots are what an upgrade can look like on this computer.
type upgradeRoots struct {
	versions []versionRoot
	// inPlace are the folders whose files an upgrade rewrites without moving
	// them: the npm that Homebrew's node copies into <prefix>/lib/node_modules.
	inPlace []versionRoot
	// shims is pyenv's shims folder, shown and resolved: the shims are
	// rewritten when pyenv itself is upgraded.
	shims versionRoot
}

// root is the folder an environment variable names, or def under home.
func (o Options) root(env, def string) string {
	if p := o.env(env); p != "" && filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(o.Home, def)
}

func (o Options) versionRoot(dir string, version *regexp.Regexp) versionRoot {
	return versionRoot{Display(o.Home, dir), o.show(realRoot(dir)), version}
}

func rootsOf(o Options) upgradeRoots {
	var r upgradeRoots
	for _, p := range brewPrefixes(o) {
		r.versions = append(r.versions, o.versionRoot(filepath.Join(p, "Cellar"), cellarVersion))
		r.inPlace = append(r.inPlace, o.versionRoot(filepath.Join(p, "lib", "node_modules"), nil))
	}
	pyenv := o.root("PYENV_ROOT", ".pyenv")
	r.versions = append(r.versions,
		o.versionRoot(filepath.Join(pyenv, "versions"), pyenvVersion),
		o.versionRoot(filepath.Join(o.root("NVM_DIR", ".nvm"), "versions", "node"), nodeVersion))
	fnm := []string{filepath.Join(o.Home, ".local", "share", "fnm"), filepath.Join(o.Home, "Library", "Application Support", "fnm"), filepath.Join(o.Home, ".fnm")}
	if p := o.env("FNM_DIR"); p != "" && filepath.IsAbs(p) {
		fnm = []string{filepath.Clean(p)}
	}
	for _, d := range fnm {
		r.versions = append(r.versions, o.versionRoot(filepath.Join(d, "node-versions"), nodeVersion))
	}
	r.shims = o.versionRoot(filepath.Join(pyenv, "shims"), nil)
	return r
}

func under(p, root string) bool { return strings.HasPrefix(p, root+"/") }

// multishell is the per-shell folder fnm puts on PATH, a link to the version
// in use. Its name changes with every shell, so all of them compare as one.
var multishell = regexp.MustCompile(`(^|/)fnm_multishells/[^/]+(/|$)`)

// sameShell rewrites the per-shell fnm folder in the paths that hold it.
func sameShell(obs watch.Observation) watch.Observation {
	if !strings.Contains(obs["entry"]+obs["target"]+obs["chain"], "fnm_multishells/") {
		return obs
	}
	out := maps.Clone(obs)
	for _, f := range []string{"entry", "target", "chain"} {
		out[f] = multishell.ReplaceAllString(out[f], "${1}fnm_multishells/*${2}")
	}
	return out
}

// upgradeShaped: every path of the tool that moved (the entry, each link
// hop, the link target and the real file) moved from one version folder to
// another inside the same version root, both as written and where the file
// really is, and nothing else about it changed. A real file that did not move
// may change only inside a folder that upgrades rewrite in place.
func upgradeShaped(old, now watch.Observation, roots upgradeRoots) bool {
	if old["kind"] != now["kind"] || old["outside"] != "" || now["outside"] != "" || old["state"] != "" || now["state"] != "" {
		return false
	}
	oc, nc := strings.Split(old["chain"], "\n"), strings.Split(now["chain"], "\n")
	if len(oc) != len(nc) {
		return false
	}
	type pair struct {
		a, b string
		real bool
	}
	pairs := []pair{{old["entry"], now["entry"], false}, {old["target"], now["target"], false}, {old["real"], now["real"], true}}
	for i := range oc {
		pairs = append(pairs, pair{oc[i], nc[i], false})
	}
	root := -1
	for _, p := range pairs {
		if p.a == p.b {
			continue
		}
		found := -1
		for i, r := range roots.versions {
			base := r.shown
			if p.real {
				base = r.real
			}
			if under(p.a, base) && under(p.b, base) && versionOnly(p.a, p.b, r.version) {
				found = i
				break
			}
		}
		if found < 0 || root >= 0 && found != root {
			return false
		}
		root = found
	}
	if root < 0 {
		return false
	}
	if old["real"] == now["real"] && old["sha256"] != now["sha256"] {
		for _, r := range roots.inPlace {
			if under(now["real"], r.real) && under(now["target"], r.shown) {
				return true
			}
		}
		return false
	}
	return true
}

// shimRewrite: a pyenv shim whose content changed and nothing else. It is an
// upgrade only beside an upgrade of pyenv itself.
func shimRewrite(old, now watch.Observation, roots upgradeRoots) bool {
	return old["kind"] == "file" && now["kind"] == "file" && old["state"] == "" && now["state"] == "" &&
		old["entry"] == now["entry"] && old["real"] == now["real"] && old["sha256"] != now["sha256"] &&
		under(now["entry"], roots.shims.shown) && under(now["real"], roots.shims.real)
}

// upgradeFinding is one medium DV-101 for every tool that looks upgraded.
func upgradeFinding(keys []string, base, cur map[string]watch.Observation) finding.Finding {
	sort.Strings(keys)
	parts := make([]string, len(keys))
	var sig []string
	for i, k := range keys {
		old, now := base[k], cur[k]
		switch {
		case old["target"] != now["target"]:
			parts[i] = k + ": " + old["target"] + " -> " + now["target"]
		case old["chain"] != now["chain"]:
			parts[i] = k + ": 링크 단계 " + changedHop(old, now)
		case old["kind"] == "file":
			parts[i] = k + ": pyenv와 함께 다시 만들어진 shim " + now["entry"]
		default:
			parts[i] = k + ": " + now["target"] + " (내용이 바뀜)"
		}
		sig = append(sig, k, now["target"], now["sha256"])
	}
	title := fmt.Sprintf("버전 폴더만 바뀐 도구 실행 파일 %d개(공식 업그레이드로 보임)", len(keys))
	return newChangeFinding("DV-101", finding.Medium, strings.Join(keys, ", "), strings.Join(parts, "; "), title, strings.Join(sig, "\x00"))
}
