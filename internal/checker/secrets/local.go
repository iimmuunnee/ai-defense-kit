package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	titleCurrent = "코드에 비밀 키가 들어 있음"
	titleLocal   = "git이 무시하는 파일에 비밀 키가 있음 (커밋된 적 없음)"
	fixLocal     = "git에 올리지 않는 지금 방식을 유지하세요. 폴더를 압축하거나 복사해 넘길 때 이 파일이 함께 나가지 않게 하고, 키를 다른 곳에 보낸 적이 있다면 폐기하고 새로 발급하세요."
)

// localOnly returns the locations, as merge writes them, of the files that git
// ignores, does not track and never committed under any ref. A key in such a
// file (a .env listed in .gitignore, say) stays on this computer unless someone
// copies the folder by other means. Any git error leaves a path out, so its
// finding keeps the usual severity.
func localOnly(ctx context.Context, root string, locs []string) map[string]bool {
	out := map[string]bool{}
	if len(locs) == 0 {
		return out
	}
	if _, err := exec.LookPath("git"); err != nil {
		return out
	}
	paths := slices.Compact(slices.Sorted(slices.Values(locs)))
	// check-ignore lists only ignored paths that git does not track. Exit 1
	// means none is ignored. Paths go in on stdin, NUL-separated: check-ignore
	// takes paths, not pathspecs, so no file name acts as a pattern.
	in := []byte(strings.Join(paths, "\x00") + "\x00")
	ign, err := gitOutput(ctx, root, in, false, "check-ignore", "--stdin", "-z")
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
		return out
	}
	for _, p := range strings.Split(string(ign), "\x00") {
		if p == "" || !slices.Contains(paths, p) {
			continue
		}
		log, err := gitOutput(ctx, root, nil, true, "log", "--all", "--format=%H", "-1", "--", p)
		if err == nil && len(bytes.TrimSpace(log)) == 0 {
			out[p] = true
		}
	}
	return out
}

// gitOutput runs git in root with the same protections as the history scan:
// safeGitConfig at command-line level and safeGitEnv. literal makes pathspecs
// literal, so a file name cannot act as a pattern; check-ignore rejects that
// setting. stdin, if not nil, is the child's input. It sets the child's
// environment only.
func gitOutput(ctx context.Context, root string, stdin []byte, literal bool, args ...string) ([]byte, error) {
	env := os.Environ()
	base := 0
	if v, ok := os.LookupEnv("GIT_CONFIG_COUNT"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("GIT_CONFIG_COUNT 값이 올바르지 않습니다: %q", v)
		}
		base = n
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(base+len(safeGitConfig)))
	for i, kv := range safeGitConfig {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", base+i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", base+i, kv[1]))
	}
	for _, kv := range safeGitEnv {
		env = append(env, kv[0]+"="+kv[1])
	}
	if literal {
		env = append(env, "GIT_LITERAL_PATHSPECS=1")
	}
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.Output()
}

// markLocal turns the current-file findings at local paths into secret-local
// findings: shown as "참고", never failing --fail-on. ID, location and evidence
// stay, so the fingerprint and any .adkignore entry for it stay too.
func markLocal(fs []finding.Finding, local map[string]bool, explain string) {
	for i := range fs {
		f := &fs[i]
		if f.Kind != "secret-current" || !local[f.Location] {
			continue
		}
		f.Kind = "secret-local"
		f.Severity = finding.Info
		f.Title = strings.Replace(f.Title, titleCurrent, titleLocal, 1)
		f.ExplainKo = explain
		f.Fix = fixLocal
	}
}
