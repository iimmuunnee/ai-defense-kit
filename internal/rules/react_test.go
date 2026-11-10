package rules

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func TestRE001SecretInBrowserEnv(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/RE-001/vulnerable", []string{"react"})
	for _, loc := range []string{".env", ".env.production", "src/client.ts", "vite.config.ts"} {
		if !hasID(got[loc], "RE-001") {
			t.Errorf("%s: want RE-001, got %+v", loc, got[loc])
		}
	}
	f := got[".env"][0]
	if f.Severity != finding.Critical || f.Confidence != finding.Certain {
		t.Errorf("severity %v, confidence %v", f.Severity, f.Confidence)
	}
	if strings.Contains(f.Evidence, "not-a-real-value") {
		t.Errorf("value shown in evidence: %q", f.Evidence)
	}
	if f.ExplainKo == "" || !strings.Contains(f.Fix, "서버") {
		t.Errorf("explain or fix missing: %q / %q", f.ExplainKo, f.Fix)
	}
}

func TestRE002TokenInBrowserEnv(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/RE-002/vulnerable", []string{"react"})
	for _, loc := range []string{".env", "src/api.js"} {
		if !hasID(got[loc], "RE-002") {
			t.Errorf("%s: want RE-002, got %+v", loc, got[loc])
		}
	}
	f := got[".env"][0]
	if f.Severity != finding.Medium || f.Confidence != finding.Suspect {
		t.Errorf("severity %v, confidence %v", f.Severity, f.Confidence)
	}
}

func TestRE003DangerouslySetInnerHTML(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/RE-003/vulnerable", []string{"react"})
	for _, loc := range []string{"src/Comment.tsx", "src/Legacy.jsx"} {
		if !hasID(got[loc], "RE-003") {
			t.Errorf("%s: want RE-003, got %+v", loc, got[loc])
		}
	}
	f := got["src/Comment.tsx"][0]
	if f.Severity != finding.Low || f.Confidence != finding.Suspect {
		t.Errorf("severity %v, confidence %v", f.Severity, f.Confidence)
	}
}

func TestReactRulesSafeExamples(t *testing.T) {
	for _, id := range []string{"RE-001", "RE-002", "RE-003"} {
		got := allFindings(t, "../../testdata/rules/"+id+"/safe", []string{"react"})
		for loc, fs := range got {
			if hasID(fs, id) {
				t.Errorf("%s: %s: unexpected finding %+v", id, loc, fs)
			}
		}
	}
}

func TestReactRulesNeedReactStack(t *testing.T) {
	for _, id := range []string{"RE-001", "RE-002", "RE-003"} {
		got := allFindings(t, "../../testdata/rules/"+id+"/vulnerable", []string{"fastapi"})
		for loc, fs := range got {
			if hasID(fs, id) {
				t.Errorf("%s ran without the react stack at %s", id, loc)
			}
		}
	}
}

func TestKoreanLoginRulesRunOnReact(t *testing.T) {
	for _, id := range []string{"KR-AUTH-001", "KR-AUTH-002"} {
		fs, _, err := Evaluate("../../testdata/rules/"+id+"/vulnerable", []string{"react"}, embedded(t), aidefensekit.Data)
		if err != nil {
			t.Fatal(err)
		}
		var hit *finding.Finding
		for i := range fs {
			if fs[i].ID == id {
				hit = &fs[i]
				break
			}
		}
		if hit == nil {
			t.Fatalf("%s did not run on the react stack", id)
		}
		if !strings.HasPrefix(hit.Fix, "# React") {
			t.Errorf("%s: fix isn't the React guide: %.40q", id, hit.Fix)
		}
	}
}

func hasID(fs []finding.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestReactEnvRulesPointAtTheRightLine(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/RE-001/vulnerable", []string{"react"})
	f := got[".env"][0]
	if f.Line != 2 || !strings.HasPrefix(f.Evidence, "VITE_") {
		t.Errorf("line %d, evidence %q", f.Line, f.Evidence)
	}
}

func TestReactEnvRulesKeepOrdinaryNamesOut(t *testing.T) {
	root := t.TempDir()
	body := strings.Join([]string{
		"VITE_SECRET_SANTA_ENABLED=true",
		"VITE_PASSWORD_MIN_LENGTH=8",
		"REACT_APP_PASSWORD_RESET_URL=https://example.test/reset",
		"VITE_API_KEY_HEADER_NAME=x-key",
		"VITE_TOKEN_EXPIRY_DAYS=7",
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := allFindings(t, root, []string{"react"}); len(got) != 0 {
		t.Errorf("ordinary names were flagged: %+v", got)
	}
}

func TestReactEnvRulesReportEveryLine(t *testing.T) {
	root := t.TempDir()
	body := "VITE_A_SECRET=1\nVITE_B=2\nREACT_APP_DB_PASSWORD=3\nVITE_C_SECRET_ACCESS_KEY=4\nVITE_A_SECRET=1\n"
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var lines []int
	seen := map[string]bool{}
	for _, f := range allFindings(t, root, []string{"react"})[".env"] {
		lines = append(lines, f.Line)
		if seen[f.Fingerprint] {
			t.Errorf("duplicate fingerprint at line %d", f.Line)
		}
		seen[f.Fingerprint] = true
	}
	// The same line twice is two findings, told apart by their order, not by the value.
	if want := []int{1, 3, 4, 5}; !slices.Equal(lines, want) {
		t.Errorf("lines = %v, want %v", lines, want)
	}
}

func TestRE003RunsOnNextjs(t *testing.T) {
	got := allFindings(t, "../../testdata/rules/RE-003/vulnerable", []string{"nextjs"})
	if !hasID(got["src/Comment.tsx"], "RE-003") {
		t.Errorf("RE-003 should run on next.js: %+v", got)
	}
}
