package aidefensekit

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

var pinnedUse = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Uses string         `yaml:"uses"`
			With map[string]any `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflows(t *testing.T) map[string]workflow {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("워크플로를 찾지 못했습니다: %v", err)
	}
	out := map[string]workflow{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf workflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("%s: YAML 문법 오류: %v", f, err)
		}
		out[filepath.Base(f)] = wf
	}
	return out
}

func TestWorkflowsParseAndPinActionsToCommits(t *testing.T) {
	for f, wf := range loadWorkflows(t) {
		if wf.Permissions["contents"] != "read" || len(wf.Permissions) != 1 {
			t.Errorf("%s: 최상위 권한은 contents: read 하나여야 합니다: %v", f, wf.Permissions)
		}
		for name, job := range wf.Jobs {
			for _, s := range job.Steps {
				if s.Uses != "" && !pinnedUse.MatchString(s.Uses) {
					t.Errorf("%s/%s: 커밋 번호로 고정하지 않은 액션: %s", f, name, s.Uses)
				}
				if regexp.MustCompile(`^actions/checkout@`).MatchString(s.Uses) && s.With["persist-credentials"] != false {
					t.Errorf("%s/%s: checkout에 persist-credentials: false가 없습니다", f, name)
				}
			}
		}
	}
}

// The secrets check runs gitleaks' rules, whose regexps take about five times
// longer on Go's standard engine than on RE2 (gitleaks' own releases build with
// this tag). Release builds and the main CI test run must use it.
func TestReleaseAndCIBuildWithRE2Tag(t *testing.T) {
	goCmd := regexp.MustCompile(`\bgo (build|test)\b`)
	tagged := regexp.MustCompile(`\bgo (build|test) [^\n]*-tags gore2regex\b`)
	read := func(name string) []string {
		raw, err := os.ReadFile(filepath.Join(".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		return regexp.MustCompile(`\r?\n`).Split(string(raw), -1)
	}
	n := 0
	for _, line := range read("release.yml") {
		if goCmd.MatchString(line) {
			n++
			if !tagged.MatchString(line) {
				t.Errorf("release.yml: -tags gore2regex가 없는 go 명령: %s", line)
			}
		}
	}
	if n < 2 {
		t.Errorf("release.yml에서 go build와 go test를 찾지 못했습니다 (%d줄)", n)
	}
	full := false
	for _, line := range read("ci.yml") {
		if tagged.MatchString(line) && regexp.MustCompile(`\./\.\.\.\s*$`).MatchString(line) {
			full = true
		}
	}
	if !full {
		t.Error("ci.yml: -tags gore2regex로 전체(./...)를 시험하는 줄이 없습니다")
	}
}

func TestReleaseWorkflowRunsOnTagsOnlyAndWritesOnlyInReleaseJob(t *testing.T) {
	wf, ok := loadWorkflows(t)["release.yml"]
	if !ok {
		t.Fatal("release.yml이 없습니다")
	}
	if len(wf.On) != 1 || wf.On["push"] == nil {
		t.Fatalf("릴리스는 push 하나로만 시작해야 합니다: %v", wf.On)
	}
	push, _ := wf.On["push"].(map[string]any)
	if _, hasBranches := push["branches"]; hasBranches || push["tags"] == nil {
		t.Fatalf("릴리스는 태그 푸시에서만 돌아야 합니다: %v", push)
	}
	for name, job := range wf.Jobs {
		hasWrite := false
		for _, v := range job.Permissions {
			if v == "write" {
				hasWrite = true
			}
		}
		if name == "release" && !hasWrite {
			t.Error("release 작업에 쓰기 권한이 없습니다")
		}
		if name != "release" && hasWrite {
			t.Errorf("%s 작업에 쓰기 권한이 있습니다", name)
		}
	}
}
