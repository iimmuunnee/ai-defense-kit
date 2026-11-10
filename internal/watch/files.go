package watch

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
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

const kindRepo = "repo-files"

// defaultRepoGlobs are the files read when globs is not set: the ones whose
// change alters what a build or an editor runs.
var defaultRepoGlobs = []string{
	".github/workflows/**", ".vscode/tasks.json",
	"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock",
}

var knownRepoOptions = map[string]bool{"root": true, "globs": true}

// repoOptions are the checked options of a repo-files target.
type repoOptions struct {
	root     string // as written
	identity string // cleaned, with forward slashes
	globs    []string
}

func parseRepoOptions(opts map[string]any) (repoOptions, error) {
	for _, k := range slices.Sorted(maps.Keys(opts)) {
		if !knownRepoOptions[k] {
			return repoOptions{}, fmt.Errorf("알 수 없는 옵션 %q입니다", k)
		}
	}
	root, ok := opts["root"].(string)
	if !ok || strings.TrimSpace(root) == "" {
		return repoOptions{}, errors.New("root 옵션에 폴더 경로를 문자열로 적어야 합니다")
	}
	root = strings.TrimSpace(root)
	r := repoOptions{root: root, identity: path.Clean(filepath.ToSlash(root)), globs: defaultRepoGlobs}
	if v, set := opts["globs"]; set {
		list, err := stringList("globs", v)
		if err != nil {
			return repoOptions{}, err
		}
		if len(list) == 0 {
			return repoOptions{}, errors.New("globs가 비어 있습니다. 감시할 파일 패턴을 하나 이상 적으세요")
		}
		r.globs = nil
		for i, g := range list {
			g = strings.TrimPrefix(strings.TrimSpace(g), "./")
			if g == "" || strings.HasPrefix(g, "/") || slices.Contains(strings.Split(g, "/"), "..") {
				return repoOptions{}, fmt.Errorf("globs의 %d번째: root 안을 가리키는 상대 패턴이어야 합니다 (/로 시작하거나 ..을 포함할 수 없습니다)", i+1)
			}
			if !doublestar.ValidatePattern(g) {
				return repoOptions{}, fmt.Errorf("globs의 %d번째: 패턴 형식이 올바르지 않습니다", i+1)
			}
			if slices.Contains(strings.Split(g, "/"), ".git") {
				// The walk never reads .git: such a glob would read clean for ever.
				return repoOptions{}, fmt.Errorf("globs의 %d번째: .git 폴더 안은 읽지 않으므로 .git을 가리키는 패턴은 쓸 수 없습니다", i+1)
			}
			r.globs = append(r.globs, g)
		}
	}
	return r, nil
}

// globsAt is the globs that apply to a path. Inside node_modules only a glob that
// names it does: `**/package-lock.json` is about the project's own lock files,
// and installs rewrite that folder and its links as routine work.
func (r repoOptions) globsAt(slash string) []string {
	if !slices.Contains(strings.Split(slash, "/"), "node_modules") {
		return r.globs
	}
	var named []string
	for _, g := range r.globs {
		if strings.Contains(g, "node_modules") {
			named = append(named, g)
		}
	}
	return named
}

func validateRepoOptions(opts map[string]any) error {
	_, err := parseRepoOptions(opts)
	return err
}

type repoObserver struct {
	open func(string) (io.ReadCloser, error) // nil means os.Open
	walk func(string, fs.WalkDirFunc) error  // nil means filepath.WalkDir
}

// NewRepoObserver returns the observer for kind "repo-files". It reads files
// only and connects nowhere.
func NewRepoObserver() Observer { return &repoObserver{} }

func (*repoObserver) Kind() string { return kindRepo }

func (o *repoObserver) hash(ctx context.Context, p string) (string, error) {
	var f io.ReadCloser
	var err error
	if o.open != nil {
		f, err = o.open(p)
	} else {
		f, err = os.Open(p)
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx, f}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ctxReader stops a long read once its context has ended.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func readFailure(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "권한이 없어 읽지 못했습니다"
	case errors.Is(err, fs.ErrNotExist):
		return "읽는 도중 사라졌습니다"
	}
	return "읽지 못했습니다"
}

// Observe hashes the files under root that match the globs. A symbolic link
// is never followed: it is recorded by the text of its target, so a link that
// leaves root neither pulls in what is outside nor hides a change of target.
func (o *repoObserver) Observe(ctx context.Context, t Target) (Observation, error) {
	r, err := parseRepoOptions(t.Options)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(r.root)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errors.New("root 폴더를 찾을 수 없습니다")
	case err != nil:
		return nil, errors.New("root 폴더를 읽지 못했습니다")
	case !info.IsDir():
		return nil, errors.New("root가 폴더가 아닙니다")
	}
	walkRoot := r.root
	if real, err := filepath.EvalSymlinks(r.root); err == nil {
		walkRoot = real
	}

	obs := Observation{"root": r.identity}
	var failures []string
	walk := o.walk
	if walk == nil {
		walk = filepath.WalkDir
	}
	err = walk(walkRoot, func(p string, d fs.DirEntry, werr error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		rel, rerr := filepath.Rel(walkRoot, p)
		if rerr != nil || rel == "." {
			if werr != nil {
				failures = append(failures, "root 폴더를 읽지 못했습니다")
			}
			return nil
		}
		slash := filepath.ToSlash(rel)
		if werr != nil {
			failures = append(failures, slash+": "+readFailure(werr))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		globs := r.globsAt(slash)
		if d.IsDir() {
			// Before it is read: a folder no glob can reach must not decide the
			// result by being unreadable. A link at this path is not a directory
			// here and takes the path below.
			if !slices.ContainsFunc(globs, func(g string) bool { return couldMatchBelow(g, slash) }) {
				return filepath.SkipDir
			}
			return nil
		}
		isLink := d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0
		matched, below := false, false
		for _, g := range globs {
			if ok, _ := doublestar.Match(g, slash); ok {
				matched = true
				break
			}
			if isLink && couldMatchBelow(g, slash) {
				below = true
			}
		}
		if !matched && !below {
			return nil
		}
		field := "file:" + slash
		// A link is recorded by its target. One that sits above a watched
		// path is recorded too: it decides what that path is.
		if isLink {
			if target, lerr := os.Readlink(p); lerr == nil {
				obs[field] = "symlink:" + filepath.ToSlash(target)
				return nil
			} else if d.Type()&fs.ModeSymlink != 0 {
				failures = append(failures, field+": "+readFailure(lerr))
				return nil
			}
		}
		if !matched {
			return nil
		}
		switch {
		case d.Type().IsRegular():
			sum, herr := o.hash(ctx, p)
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if herr != nil {
				failures = append(failures, field+": "+readFailure(herr))
				return nil
			}
			obs[field] = sum
		default:
			obs[field] = "non-regular-file"
		}
		return nil
	})
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, PartialError{Obs: obs, Err: errDeadline}
	}
	if err != nil {
		return nil, err
	}
	if len(failures) > 0 {
		slices.Sort(failures)
		msg := "파일을 다 읽지 못했습니다: " + strings.Join(failures[:min(len(failures), 3)], "; ")
		if len(failures) > 3 {
			msg += fmt.Sprintf(" 외 %d건", len(failures)-3)
		}
		return nil, PartialError{Obs: obs, Err: errors.New(msg)}
	}
	return obs, nil
}

// checkInitialRepo refuses a root that matches no file: a wrong root or glob
// would read clean forever.
func checkInitialRepo(t Target, obs Observation) error {
	for k := range obs {
		if strings.HasPrefix(k, "file:") {
			return nil
		}
	}
	return fmt.Errorf("대상 %s: root 안에서 globs에 맞는 파일을 하나도 찾지 못했습니다. root나 globs가 잘못되었을 수 있습니다", t.Key)
}

// couldMatchBelow reports whether glob could match some path below dir (or
// dir itself), so that a link at dir decides what a watched path is and a
// folder no glob can reach need not be read. When in doubt it says yes: a link
// recorded needlessly costs one field, a folder walked needlessly some time,
// and a wrong no would hide a file.
func couldMatchBelow(glob, dir string) bool {
	// Braces, escapes and a class holding "/" do not split at "/" as written.
	if strings.ContainsAny(glob, `{}\`) {
		return true
	}
	ps, ds := strings.Split(glob, "/"), strings.Split(dir, "/")
	for _, p := range ps {
		if strings.Count(p, "[") != strings.Count(p, "]") {
			return true
		}
	}
	for i, d := range ds {
		if i >= len(ps) {
			return false
		}
		if ps[i] == "**" {
			return true
		}
		if ok, _ := doublestar.Match(ps[i], d); !ok {
			return false
		}
	}
	// Every segment of dir matched: something below it can match if the glob goes deeper.
	return len(ps) > len(ds)
}
