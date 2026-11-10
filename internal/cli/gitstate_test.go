package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git이 없어 건너뜁니다")
	}
}

func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func writeT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// newGitRepo는 user 설정이 들어간 임시 저장소를 만든다.
func newGitRepo(t *testing.T) string {
	t.Helper()
	needGit(t)
	dir := t.TempDir()
	runGitT(t, dir, "init", "-q")
	runGitT(t, dir, "config", "user.name", "t")
	runGitT(t, dir, "config", "user.email", "t@example.com")
	runGitT(t, dir, "config", "commit.gpgsign", "false")
	// 커밋 뒤 백그라운드 정리가 잠금 파일을 만들었다 지우면 저장소 복사가 흔들린다.
	runGitT(t, dir, "config", "maintenance.auto", "false")
	runGitT(t, dir, "config", "gc.auto", "0")
	return dir
}

func commitAll(t *testing.T, dir string) {
	t.Helper()
	runGitT(t, dir, "add", "-A")
	runGitT(t, dir, "commit", "-q", "-m", "init")
}

func TestGitDirtyStates(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, "a.txt"), "hello\n")
	commitAll(t, repo)
	ctx := context.Background()
	if got := gitDirty(ctx, repo); got != dirtyNo {
		t.Fatalf("깨끗한 저장소: %q", got)
	}
	writeT(t, filepath.Join(repo, "a.txt"), "changed\n")
	if got := gitDirty(ctx, repo); got != dirtyYes {
		t.Fatalf("추적 파일 수정: %q", got)
	}
	runGitT(t, repo, "checkout", "--", "a.txt")
	writeT(t, filepath.Join(repo, "new.txt"), "x\n")
	if got := gitDirty(ctx, repo); got != dirtyYes {
		t.Fatalf("새 파일: %q", got)
	}
	if got := gitDirty(ctx, t.TempDir()); got != dirtyUnknown {
		t.Fatalf("저장소 아님: %q", got)
	}
}

func TestGitDirtyWholeRepo(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, "apps/web/w.txt"), "w\n")
	writeT(t, filepath.Join(repo, "apps/api/a.txt"), "a\n")
	commitAll(t, repo)
	writeT(t, filepath.Join(repo, "apps/api/a.txt"), "changed\n")
	if got := gitDirty(context.Background(), filepath.Join(repo, "apps/web")); got != dirtyYes {
		t.Fatalf("하위 폴더에서도 저장소 전체를 봐야 합니다: %q", got)
	}
}

func TestGitDirtyGitignoredIsNo(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, ".gitignore"), "ignored.txt\n")
	writeT(t, filepath.Join(repo, "a.txt"), "a\n")
	commitAll(t, repo)
	writeT(t, filepath.Join(repo, "ignored.txt"), "secret\n")
	if got := gitDirty(context.Background(), repo); got != dirtyNo {
		t.Fatalf("무시된 파일만 있으면 no여야 합니다: %q", got)
	}
}

func quoteSh(p string) string { return "'" + filepath.ToSlash(p) + "'" }

func copyRepoTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if os.IsNotExist(err) {
			return nil // 걷는 사이 git이 지운 임시 파일
		}
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, b, info.Mode()); err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGitDirtyDoesNotRunRepoCommands(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, repo, marker string)
	}{
		{"fsmonitor", func(t *testing.T, repo, marker string) {
			runGitT(t, repo, "config", "core.fsmonitor", "touch "+quoteSh(marker)+" #")
		}},
		{"filter-clean", func(t *testing.T, repo, marker string) {
			writeT(t, filepath.Join(repo, ".gitattributes"), "a.txt filter=evil\n")
			runGitT(t, repo, "config", "filter.evil.clean", "touch "+quoteSh(marker)+"; cat")
		}},
		{"filter-process", func(t *testing.T, repo, marker string) {
			writeT(t, filepath.Join(repo, ".gitattributes"), "a.txt filter=evil\n")
			runGitT(t, repo, "config", "filter.evil.process", "touch "+quoteSh(marker))
		}},
		{"post-index-change", func(t *testing.T, repo, marker string) {
			writeT(t, filepath.Join(repo, ".git/hooks/post-index-change"), "#!/bin/sh\ntouch "+quoteSh(marker)+"\n")
			// 내용은 같고 mtime만 다른 추적 파일: status가 인덱스를 반드시 다시 쓰게 한다.
			writeT(t, filepath.Join(repo, "b.txt"), "same\n")
			runGitT(t, repo, "add", "b.txt")
			runGitT(t, repo, "commit", "-q", "-m", "b")
			future := time.Now().Add(time.Hour)
			if err := os.Chtimes(filepath.Join(repo, "b.txt"), future, future); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := newGitRepo(t)
			writeT(t, filepath.Join(repo, "a.txt"), "hello\n")
			commitAll(t, repo)
			marker := filepath.Join(t.TempDir(), "marker")
			c.setup(t, repo, marker)
			if c.name == "filter-clean" || c.name == "filter-process" {
				// 필터 설정 이후 내용이 같은 크기로 바뀌어야 git이 내용을 비교하며 필터를 부른다.
				// 이 add도 필터를 부를 수 있고, 프로토콜을 모르는 가짜 필터면 실패한다. 판정은 뒤에서 한다.
				add := exec.Command("git", "-C", repo, "add", ".gitattributes")
				if out, err := add.CombinedOutput(); err != nil {
					t.Logf("git add: %v: %s", err, out)
				}
			}
			writeT(t, filepath.Join(repo, "a.txt"), "world\n")

			// 대조군: 같은 설정의 복사본에서 평범한 git status가 표식을 만들어야 한다.
			ctrl := t.TempDir()
			copyRepoTree(t, repo, ctrl)
			cmd := exec.Command("git", "-C", ctrl, "status", "--porcelain")
			out, _ := cmd.CombinedOutput()
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("대조군이 동작하지 않았습니다(설정 오류): git status 출력=%q", out)
			}
			os.Remove(marker)

			if got := gitDirty(context.Background(), repo); got != dirtyYes {
				t.Fatalf("gitDirty=%q", got)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatalf("gitDirty가 저장소 설정의 명령을 실행했습니다")
			}
		})
	}
}

func TestGitDirtyRejectsOddFilterName(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, "a.txt"), "hello\n")
	commitAll(t, repo)
	marker := filepath.Join(t.TempDir(), "marker")
	writeT(t, filepath.Join(repo, ".gitattributes"), "a.txt filter=a=b\n")
	runGitT(t, repo, "config", "filter.a=b.clean", "touch "+quoteSh(marker)+"; cat")
	writeT(t, filepath.Join(repo, "a.txt"), "world\n")

	ctrl := t.TempDir()
	copyRepoTree(t, repo, ctrl)
	out, _ := exec.Command("git", "-C", ctrl, "status", "--porcelain").CombinedOutput()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("대조군이 동작하지 않았습니다(설정 오류): git status 출력=%q", out)
	}
	os.Remove(marker)

	if got := gitDirty(context.Background(), repo); got != dirtyUnknown {
		t.Fatalf("이상한 필터 이름은 unknown이어야 합니다: %q", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("명령이 실행되었습니다")
	}
}

func TestGitPrefix(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, "apps/web/w.txt"), "w\n")
	commitAll(t, repo)
	ctx := context.Background()
	if got := gitPrefix(ctx, repo); got != "" {
		t.Fatalf("최상위: %q", got)
	}
	if got := gitPrefix(ctx, filepath.Join(repo, "apps/web")); got != "apps/web/" {
		t.Fatalf("하위 폴더: %q", got)
	}
	if got := gitPrefix(ctx, t.TempDir()); got != "" {
		t.Fatalf("저장소 밖: %q", got)
	}
	if strings.Contains(gitPrefix(ctx, filepath.Join(repo, "apps/web")), "\\") {
		t.Fatal("역슬래시 금지")
	}
}

func dirtyRepoAndClean(t *testing.T) (dirty, clean string) {
	t.Helper()
	dirty = newGitRepo(t)
	writeT(t, filepath.Join(dirty, "a.txt"), "hello\n")
	commitAll(t, dirty)
	writeT(t, filepath.Join(dirty, "a.txt"), "changed\n")
	clean = newGitRepo(t)
	writeT(t, filepath.Join(clean, "c.txt"), "c\n")
	commitAll(t, clean)
	return
}

func TestGitDirtyShowUntrackedNoStillYes(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, "a.txt"), "a\n")
	commitAll(t, repo)
	runGitT(t, repo, "config", "status.showUntrackedFiles", "no")
	writeT(t, filepath.Join(repo, "new.txt"), "x\n")
	if got := gitDirty(context.Background(), repo); got != dirtyYes {
		t.Fatalf("새 파일은 설정과 관계없이 yes여야 합니다: %q", got)
	}
}

func TestGitDirtyGitlinkIsUnknown(t *testing.T) {
	repo := newGitRepo(t)
	writeT(t, filepath.Join(repo, "a.txt"), "a\n")
	commitAll(t, repo)
	runGitT(t, repo, "update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,sub")
	if got := gitDirty(context.Background(), repo); got != dirtyUnknown {
		t.Fatalf("서브모듈이 있으면 unknown이어야 합니다: %q", got)
	}
}

func TestGitDirtyHiddenFlagsAreUnknown(t *testing.T) {
	for _, flag := range []string{"--assume-unchanged", "--skip-worktree"} {
		t.Run(flag, func(t *testing.T) {
			repo := newGitRepo(t)
			writeT(t, filepath.Join(repo, "a.txt"), "hello\n")
			commitAll(t, repo)
			runGitT(t, repo, "update-index", flag, "a.txt")
			writeT(t, filepath.Join(repo, "a.txt"), "changed\n")
			if got := gitDirty(context.Background(), repo); got != dirtyUnknown {
				t.Fatalf("%s: %q", flag, got)
			}
		})
	}
}

func TestGitDirtyIgnoresInheritedGitEnv(t *testing.T) {
	dirty, clean := dirtyRepoAndClean(t)
	t.Setenv("GIT_DIR", filepath.Join(clean, ".git"))
	t.Setenv("GIT_WORK_TREE", clean)
	ctx := context.Background()
	if got := gitDirty(ctx, dirty); got != dirtyYes {
		t.Fatalf("상속된 GIT_DIR에 속으면 안 됩니다: %q", got)
	}
	writeT(t, filepath.Join(dirty, "sub/x.txt"), "x\n")
	if got := gitPrefix(ctx, filepath.Join(dirty, "sub")); got != "sub/" {
		t.Fatalf("gitPrefix가 상속된 환경을 따랐습니다: %q", got)
	}
}

func TestGitDirtyCoreWorktreeElsewhereIsUnknown(t *testing.T) {
	dirty, clean := dirtyRepoAndClean(t)
	runGitT(t, dirty, "config", "core.worktree", clean)
	if got := gitDirty(context.Background(), dirty); got == dirtyNo {
		t.Fatalf("다른 트리를 가리켜 거짓 no가 나왔습니다")
	} else if got != dirtyUnknown {
		t.Fatalf("unknown이어야 합니다: %q", got)
	}
}
