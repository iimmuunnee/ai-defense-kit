package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	dirtyYes     = "yes"
	dirtyNo      = "no"
	dirtyUnknown = "unknown"
)

const gitStateTimeout = 30 * time.Second

// filterNameRe는 -c 로 안전하게 덮어쓸 수 있는 필터 이름이다.
// '='가 있으면 -c 가 첫 '='에서 키와 값을 나누므로 필터를 끌 수 없다.
var filterNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// safeGitCmd는 점검 대상 저장소의 설정이 명령을 실행하지 못하도록
// 환경을 제한한 git 명령을 만든다. 프로세스 환경은 건드리지 않는다.
func safeGitCmd(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	var env []string
	for _, kv := range os.Environ() {
		if isRedirectingGitEnv(kv) {
			continue
		}
		env = append(env, kv)
	}
	for _, kv := range safeGitEnv {
		env = append(env, kv[0]+"="+kv[1])
	}
	cmd.Env = env
	return cmd
}

// 상속된 환경 변수로 다른 저장소·작업 트리를 보게 되는 것을 막는다.
var redirectingGitEnv = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
	"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_PREFIX", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES",
	"GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_QUARANTINE_PATH",
}

func isRedirectingGitEnv(kv string) bool {
	name, _, _ := strings.Cut(kv, "=")
	for _, r := range redirectingGitEnv {
		if strings.EqualFold(name, r) {
			return true
		}
	}
	return false
}

// pathInside는 root가 top 안(또는 같은 곳)에 있는지 심볼릭 링크를 풀어 비교한다.
func pathInside(root, top string) bool {
	r, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	t, err := filepath.EvalSymlinks(filepath.FromSlash(top))
	if err != nil {
		return false
	}
	r, err1 := filepath.Abs(r)
	t, err2 := filepath.Abs(t)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(t, r)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// 외부 설정이 지연 조회·프롬프트를 일으키지 않게 하는 환경 변수.
var safeGitEnv = [][2]string{
	{"GIT_NO_LAZY_FETCH", "1"},
	{"GIT_ALLOW_PROTOCOL", "none"},
	{"GIT_TERMINAL_PROMPT", "0"},
}

// gitFilterNames는 저장소 설정에 있는 filter.<이름>.* 의 이름 목록을 읽는다.
// 설정을 읽기만 하므로 명령이 실행되지 않는다.
func gitFilterNames(ctx context.Context, root string) ([]string, error) {
	cmd := safeGitCmd(ctx, "-C", root, "config", "--name-only", "--get-regexp", `^filter\.`)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil // 일치하는 키 없음
		}
		return nil, err
	}
	seen := map[string]bool{}
	for _, key := range strings.Split(stdout.String(), "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		rest := strings.TrimPrefix(key, "filter.")
		i := strings.LastIndex(rest, ".")
		if i < 0 {
			continue // filter.<변수> 형태, 이름 없음
		}
		seen[rest[:i]] = true
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// gitDirty는 root가 속한 저장소 전체에 커밋되지 않은 변경이 있는지 본다.
// 하위 폴더를 넘겨도 범위는 저장소 전체이고 제외하는 파일은 없다.
// 점검 대상 저장소의 설정(fsmonitor, 필터, 훅)이 명령을 실행하지 못하게
// 막으며, 어느 단계든 실패하면 "unknown"이다.
func gitDirty(ctx context.Context, root string) string {
	ctx, cancel := context.WithTimeout(ctx, gitStateTimeout)
	defer cancel()

	names, err := gitFilterNames(ctx, root)
	if err != nil {
		return dirtyUnknown
	}
	for _, n := range names {
		if !filterNameRe.MatchString(n) {
			return dirtyUnknown
		}
	}

	top, err := safeGitCmd(ctx, "-C", root, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return dirtyUnknown
	}
	toplevel := strings.TrimSpace(string(top))
	if toplevel == "" {
		return dirtyUnknown
	}

	if !pathInside(root, toplevel) {
		return dirtyUnknown // core.worktree 등으로 다른 트리를 가리킴
	}

	base := []string{
		"--no-optional-locks", "-C", toplevel,
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=" + os.DevNull,
	}
	for _, n := range names {
		for _, k := range []string{"clean", "smudge", "process"} {
			base = append(base, "-c", "filter."+n+"."+k+"=")
		}
		base = append(base, "-c", "filter."+n+".required=false")
	}
	run := func(sub ...string) ([]byte, error) {
		return safeGitCmd(ctx, append(append([]string{}, base...), sub...)...).Output()
	}

	// 서브모듈(gitlink)은 --ignore-submodules=all 이 변경을 가리므로 판단하지 않는다.
	staged, err := run("ls-files", "-s")
	if err != nil {
		return dirtyUnknown
	}
	for _, line := range strings.Split(string(staged), "\n") {
		if strings.HasPrefix(line, "160000 ") {
			return dirtyUnknown
		}
	}

	out, err := run("status", "--porcelain", "--ignore-submodules=all", "--untracked-files=normal")
	if err != nil {
		return dirtyUnknown
	}
	if len(bytes.TrimSpace(out)) > 0 {
		return dirtyYes
	}

	// assume-unchanged, skip-worktree 파일은 status가 변경을 가린다.
	tags, err := run("ls-files", "-v")
	if err != nil {
		return dirtyUnknown
	}
	for _, line := range strings.Split(string(tags), "\n") {
		if line == "" {
			continue
		}
		if c := line[0]; c == 'S' || (c >= 'a' && c <= 'z') {
			return dirtyUnknown
		}
	}
	return dirtyNo
}

// gitPrefix는 root의 저장소 기준 경로 접두사를 돌려준다(예: "apps/web/").
// 저장소 밖이거나 실패하면 "".
func gitPrefix(ctx context.Context, root string) string {
	ctx, cancel := context.WithTimeout(ctx, gitStateTimeout)
	defer cancel()
	out, err := safeGitCmd(ctx, "-C", root, "rev-parse", "--show-prefix").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
