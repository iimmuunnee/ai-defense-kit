package cicd

import (
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func TestRiskyFixture(t *testing.T) {
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: "../../../testdata/cicd/risky"})
	if err != nil || len(res.Warnings) != 0 {
		t.Fatalf("%v %+v", err, res.Warnings)
	}
	type row struct {
		file, id string
		sev      finding.Severity
	}
	var got []row
	for _, f := range res.Findings {
		got = append(got, row{f.Location, f.ID, f.Severity})
		if f.ExplainKo == "" || f.Fix == "" {
			t.Errorf("%s has no texts", f.ID)
		}
	}
	want := []row{
		{".github/workflows/deploy.yml", "CI-003", finding.High},
		{".github/workflows/deploy.yml", "CI-002", finding.Low},
		{".github/workflows/deploy.yml", "CI-002", finding.Medium},
		{".github/workflows/deploy.yml", "CI-001", finding.High},
		{".github/workflows/deploy.yml", "CI-001", finding.High},
		{".github/workflows/pr-target.yml", "CI-002", finding.Low},
		{".github/workflows/pr-target.yml", "CI-004", finding.Critical},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCleanFixture(t *testing.T) {
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: "../../../testdata/cicd/clean"})
	if err != nil || len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
}

var forbidden = []string{"막는다", "안전", "방어한다"}

func TestTextsExistAndFollowRules(t *testing.T) {
	longHex := regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	must := map[string][]string{
		"CI-001": {"role-to-assume", "id-token: write", "확인 필요"},
		"CI-002": {"커밋 해시"},
		"CI-003": {"permissions"},
		"CI-004": {"gh pr checkout", "git fetch", "pull_request_target"},
		"CI-005": {"읽지 않", "GitHub"},
	}
	for _, id := range []string{"CI-001", "CI-002", "CI-003", "CI-004", "CI-005"} {
		for _, name := range []string{"explain/" + id + ".md", "fixes/" + id + "/github-actions.md"} {
			b, err := fs.ReadFile(aidefensekit.Data, name)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			s := string(b)
			if strings.TrimSpace(s) == "" {
				t.Errorf("%s is empty", name)
			}
			for _, w := range forbidden {
				if strings.Contains(s, w) {
					t.Errorf("%s contains %q", name, w)
				}
			}
			if longHex.MatchString(s) || strings.Contains(s, "AKIA") {
				t.Errorf("%s holds a key-looking or hash-looking string", name)
			}
			if strings.HasPrefix(name, "explain/") {
				for _, m := range must[id] {
					if !strings.Contains(s, m) {
						t.Errorf("%s lacks %q", name, m)
					}
				}
			}
		}
	}
}
