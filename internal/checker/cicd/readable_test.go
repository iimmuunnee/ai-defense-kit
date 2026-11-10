package cicd

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// genWords makes n 6-letter lowercase words from a hash, in memory.
func genWords(seed string, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		sum := sha256.Sum256([]byte(seed + string(rune('a'+i))))
		w := make([]byte, 6)
		for j := range w {
			w[j] = 'a' + sum[j]%26
		}
		out = append(out, string(w))
	}
	return out
}

// throughRunAll runs the checker the way adk scan does, so the last net in
// RunAll is part of what is checked.
func throughRunAll(t *testing.T, body string) []finding.Finding {
	t.Helper()
	root := repo(t, map[string]string{"w.yml": body})
	got, st := checker.RunAll(context.Background(), []checker.Checker{New(testData)}, checker.Target{Root: root}, 0)
	if st[0].Status != checker.StatusOK {
		t.Fatalf("status %+v", st[0])
	}
	return got
}

func only(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	var out []finding.Finding
	for _, f := range fs {
		if f.ID == id {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("%s findings = %d: %+v", id, len(out), fs)
	}
	return out[0]
}

// I1: 저장소에서 온 이름(작업 이름)만 따로 검사하고, 도구가 만든 문장은 세지 않는다.
func TestEvidenceKeepsKeyNameAndJobName(t *testing.T) {
	body := permsRead + "jobs:\n  deploy-to-aws-prod:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - run: ./deploy.sh\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ID }}\n"
	f := only(t, throughRunAll(t, body), "CI-001")
	if f.Evidence != "AWS_ACCESS_KEY_ID (작업 deploy-to-aws-prod 단계 1 env)" {
		t.Errorf("CI-001 evidence %q", f.Evidence)
	}

	body = "on: pull_request_target\n" + permsRead + "jobs:\n  build-and-test:\n    steps:\n" +
		"      - uses: actions/checkout@v4\n        with:\n          ref: " + prHead + "\n"
	f = only(t, throughRunAll(t, body), "CI-004")
	for _, want := range []string{"github.event.pull_request.head", "build-and-test", "actions/checkout"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("CI-004 evidence %q lacks %q", f.Evidence, want)
		}
	}
	if strings.Contains(f.Evidence+f.Title, "가림") {
		t.Errorf("CI-004 %q / %q", f.Evidence, f.Title)
	}
}

// 이름 자체가 단어 나열이면(구분 문자가 섞여도, 대문자여도) 그 이름만 가린다.
func TestPhraseShapedNamesStayHidden(t *testing.T) {
	w := genWords("b3-cicd", 12)
	up := strings.ToUpper(strings.Join(w[:6], "_")) + "-" + strings.Join(w[6:], ".")
	body := permsRead + "jobs:\n  " + up + ":\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: " + w[0] + "/" + strings.Join(w[1:], "-") + "@main\n" +
		"      - run: x\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ID }}\n"
	fs := throughRunAll(t, body)
	if len(fs) < 2 {
		t.Fatalf("findings = %d", len(fs))
	}
	for _, f := range fs {
		text := strings.ToLower(f.Evidence + " " + f.Title)
		for _, word := range w {
			if strings.Contains(text, word) {
				t.Errorf("%s: word shown: %q", f.ID, text)
				break
			}
		}
	}
	if f := only(t, fs, "CI-001"); !strings.HasPrefix(f.Evidence, "AWS_ACCESS_KEY_ID (작업 ") {
		t.Errorf("CI-001 evidence %q", f.Evidence)
	}
}

// M5: toJSON(secrets)처럼 secrets 전체를 넘기는 식도 secrets를 읽는 식이다.
func TestSecretsWholeObjectCountsAsSecrets(t *testing.T) {
	for _, v := range []string{"${{ toJSON(secrets) }}", "${{ fromJSON(toJSON(secrets)).AWS_ID }}", "${{ secrets }}"} {
		body := permsRead + "jobs:\n  a:\n    env:\n      AWS_ACCESS_KEY_ID: " + v + "\n    steps:\n      - run: echo\n"
		got := byID(runOne(t, body), "CI-001")
		if len(got) != 1 || got[0].Severity != finding.High || got[0].Confidence != finding.Certain {
			t.Errorf("%s: %+v", v, got)
		}
	}
	// 이름에 secrets가 들어 있을 뿐인 식은 여전히 secrets가 아니다.
	body := permsRead + "jobs:\n  a:\n    env:\n      AWS_ACCESS_KEY_ID: ${{ steps.mysecrets_x.outputs.k }}\n    steps:\n      - run: echo\n"
	if got := byID(runOne(t, body), "CI-001"); len(got) != 1 || got[0].Severity != finding.Medium {
		t.Errorf("mysecrets_x: %+v", got)
	}
}
