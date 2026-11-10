package deps

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	warnLockfileLink = "링크로 된 잠금 파일은 대조하지 못했습니다. 직접 확인해 주세요"
	warnNoLockBeside = "잠금 파일이 없는 package.json의 의존성은 버전을 알 수 없어 대조하지 못했습니다"

	maxPackageJSON = 1 << 20
)

var lockfileNames = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}

// lockfileWarnings names what the scanner silently passes over while it reads
// other lockfiles: a link with a lockfile name, and a package.json with
// dependencies and no lockfile beside it or above it within root. A warning, not a
// failure: a failed checker's findings are discarded. Output cleans the names.
func lockfileWarnings(root string) []string {
	var links, bare []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
		case d.IsDir():
			if p != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
		case !d.Type().IsRegular():
			if slices.Contains(lockfileNames, d.Name()) {
				links = append(links, finding.NormalizePath(root, p))
			}
		case d.Name() == "package.json" && declaresDependencies(p) && !lockfileAbove(root, filepath.Dir(p)):
			bare = append(bare, finding.NormalizePath(root, p))
		}
		return nil
	})
	var out []string
	if len(links) > 0 {
		out = append(out, warnLockfileLink+": "+nameList(links))
	}
	if len(bare) > 0 {
		out = append(out, warnNoLockBeside+": "+nameList(bare))
	}
	return out
}

// declaresDependencies reports a readable package.json listing a dependency. One
// that cannot be read is left to the autorun checker, which reports it.
func declaresDependencies(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var pkg struct {
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
	}
	if json.NewDecoder(io.LimitReader(f, maxPackageJSON)).Decode(&pkg) != nil {
		return false
	}
	return len(pkg.Dependencies)+len(pkg.DevDependencies)+len(pkg.OptionalDependencies) > 0
}

// lockfileAbove looks for a regular lockfile in dir and its parents up to root.
func lockfileAbove(root, dir string) bool {
	for {
		for _, name := range lockfileNames {
			if st, err := os.Lstat(filepath.Join(dir, name)); err == nil && st.Mode().IsRegular() {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if dir == root || parent == dir {
			return false
		}
		dir = parent
	}
}
