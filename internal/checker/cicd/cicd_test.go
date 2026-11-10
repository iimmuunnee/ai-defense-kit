package cicd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

var testData = fstest.MapFS{
	"explain/CI-001.md":              {Data: []byte("설명1")},
	"explain/CI-002.md":              {Data: []byte("설명2")},
	"explain/CI-003.md":              {Data: []byte("설명3")},
	"explain/CI-004.md":              {Data: []byte("설명4")},
	"fixes/CI-001/github-actions.md": {Data: []byte("수정1")},
	"fixes/CI-002/github-actions.md": {Data: []byte("수정2")},
	"fixes/CI-003/github-actions.md": {Data: []byte("수정3")},
	"fixes/CI-004/github-actions.md": {Data: []byte("수정4")},
	"explain/CI-005.md":              {Data: []byte("설명5")},
	"fixes/CI-005/github-actions.md": {Data: []byte("수정5")},
}

// repo writes workflow files under .github/workflows of a new temp folder.
func repo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, ".github", "workflows", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func run(t *testing.T, root string) checker.Result {
	t.Helper()
	res, err := New(testData).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func runOne(t *testing.T, body string) checker.Result {
	t.Helper()
	return run(t, repo(t, map[string]string{"w.yml": body}))
}

func byID(res checker.Result, id string) []finding.Finding {
	var out []finding.Finding
	for _, f := range res.Findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

// lineOf is the 1-based number of the first line containing sub.
func lineOf(t *testing.T, body, sub string) int {
	t.Helper()
	for i, l := range strings.Split(body, "\n") {
		if strings.Contains(l, sub) {
			return i + 1
		}
	}
	t.Fatalf("%q not in body", sub)
	return 0
}

// permsRead is a workflow-level permissions block that keeps CI-003 quiet.
const permsRead = "permissions:\n  contents: read\n"

func TestName(t *testing.T) {
	if New(testData).Name() != "cicd" {
		t.Fatal("name")
	}
}

func TestNoWorkflowFolder(t *testing.T) {
	res := run(t, t.TempDir())
	if len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestOnlyRootWorkflowFolderIsRead(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sub", ".github", "workflows", "w.yml")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"), 0o644)
	// a subfolder of the workflow folder is not read either
	p = filepath.Join(root, ".github", "workflows", "nested", "w.yml")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"), 0o644)
	// nor a file that is not yml or yaml
	os.WriteFile(filepath.Join(root, ".github", "workflows", "notes.txt"), []byte("uses: x/y@main"), 0o644)
	res := run(t, root)
	if len(res.Findings) != 0 || len(res.Warnings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestYamlExtensionsAndCase(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"
	root := repo(t, map[string]string{"a.yaml": body, "B.YML": body})
	res := run(t, root)
	got := byID(res, "CI-002")
	if len(got) != 2 {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestCI001Detected(t *testing.T) {
	body := permsRead + `jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@0123456789abcdef0123456789abcdef01234567
        with:
          aws-access-key-id: ${{ secrets.X }}
          aws-region: ap-northeast-2
      - run: ./deploy.sh
        env:
          AWS_SECRET_ACCESS_KEY: ${{ secrets.Y }}
`
	res := runOne(t, body)
	got := byID(res, "CI-001")
	if len(got) != 2 {
		t.Fatalf("%+v", res.Findings)
	}
	f := got[0]
	if f.Line != lineOf(t, body, "aws-access-key-id") || f.Location != ".github/workflows/w.yml" ||
		f.Severity != finding.High || f.Confidence != finding.Certain || f.Source != "cicd" || f.Kind != "CI-001" ||
		f.ExplainKo != "설명1" || f.Fix != "수정1" || !strings.Contains(f.Evidence, "aws-access-key-id") ||
		!strings.Contains(f.Evidence, "deploy") || f.Fingerprint == "" {
		t.Fatalf("%+v", f)
	}
	g := got[1]
	if g.Line != lineOf(t, body, "AWS_SECRET_ACCESS_KEY") || !strings.Contains(g.Evidence, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("%+v", g)
	}
	if f.Title == "" || f.Title != g.Title || strings.Contains(f.Title, "deploy") {
		t.Errorf("title must be fixed text: %q", f.Title)
	}
}

func TestCI001EnvLevels(t *testing.T) {
	body := permsRead + `env:
  AWS_ACCESS_KEY_ID: ${{ secrets.A }}
jobs:
  one:
    env:
      aws_secret_access_key: ${{ secrets.B }}
    steps:
      - run: echo
        env:
          Aws_Access_Key_Id: ${{ secrets.C }}
`
	res := runOne(t, body)
	got := byID(res, "CI-001")
	if len(got) != 3 {
		t.Fatalf("%+v", res.Findings)
	}
	wantLines := []int{lineOf(t, body, "AWS_ACCESS_KEY_ID"), lineOf(t, body, "aws_secret_access_key"), lineOf(t, body, "Aws_Access_Key_Id")}
	for i, f := range got {
		if f.Line != wantLines[i] {
			t.Errorf("finding %d line = %d, want %d (%+v)", i, f.Line, wantLines[i], f)
		}
	}
	// canonical names in evidence whatever the case in the file
	if !strings.Contains(got[1].Evidence, "AWS_SECRET_ACCESS_KEY") || !strings.Contains(got[2].Evidence, "AWS_ACCESS_KEY_ID") {
		t.Errorf("%q %q", got[1].Evidence, got[2].Evidence)
	}
}

func TestCI001OtherClouds(t *testing.T) {
	body := permsRead + `jobs:
  deploy:
    steps:
      - uses: google-github-actions/auth@0123456789abcdef0123456789abcdef01234567
        with:
          credentials_json: ${{ secrets.GCP }}
      - uses: Azure/Login@0123456789abcdef0123456789abcdef01234567
        with:
          creds: ${{ secrets.AZ }}
      - uses: other/thing@0123456789abcdef0123456789abcdef01234567
        with:
          creds: ${{ secrets.NOT_AZURE }}
          credentials_json: ${{ secrets.NOT_GCP }}
`
	res := runOne(t, body)
	got := byID(res, "CI-001")
	if len(got) != 2 {
		t.Fatalf("%+v", res.Findings)
	}
	if got[0].Line != lineOf(t, body, "credentials_json: ${{ secrets.GCP") || got[1].Line != lineOf(t, body, "creds: ${{ secrets.AZ") {
		t.Fatalf("%+v", got)
	}
}

func TestCI001RoleOnlyIsClean(t *testing.T) {
	body := permsRead + `jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@0123456789abcdef0123456789abcdef01234567
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: ap-northeast-2
`
	res := runOne(t, body)
	if len(res.Findings) != 0 {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestCI001EmptyValueIsNotAKey(t *testing.T) {
	body := permsRead + `jobs:
  a:
    env:
      AWS_ACCESS_KEY_ID:
      AWS_SECRET_ACCESS_KEY: ""
    steps:
      - run: echo
`
	if got := byID(runOne(t, body), "CI-001"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

// The scanned value must never reach the report, directly or through the
// fingerprint, whatever it looks like and wherever it is.
func TestCI001NeverPrintsValue(t *testing.T) {
	canaryID := "AKIA" + "QQQQWWWWEEEERRRR"
	canarySecret := "q1w2e3r4" + "t5y6u7i8o9p0" + "ZXCVBNMasdfghjkl"
	build := func(id, secret string) string {
		return permsRead + `jobs:
  deploy:
    env:
      AWS_SECRET_ACCESS_KEY: ` + secret + `
    steps:
      - uses: aws-actions/configure-aws-credentials@0123456789abcdef0123456789abcdef01234567
        with:
          aws-access-key-id: ${{ secrets.X }} ` + id + `
`
	}
	res := runOne(t, build(canaryID, canarySecret))
	if len(byID(res, "CI-001")) != 2 {
		t.Fatalf("%+v", res.Findings)
	}
	all, _ := json.Marshal(res)
	for _, c := range []string{canaryID, canarySecret, "q1w2e3r4"} {
		if strings.Contains(string(all), c) {
			t.Fatalf("value leaked into result: %s", all)
		}
	}
	// the fingerprint does not depend on the value
	other := runOne(t, build("AKIA"+"ZZZZXXXXCCCCVVVV", "different"+"secretvalue1234567890"))
	if len(other.Findings) != len(res.Findings) {
		t.Fatal("count differs")
	}
	for i := range res.Findings {
		if res.Findings[i].Fingerprint != other.Findings[i].Fingerprint {
			t.Errorf("fingerprint depends on the value: %+v", res.Findings[i])
		}
	}
}

func TestCI002(t *testing.T) {
	sha := strings.Repeat("a1", 20)
	cases := []struct {
		uses string
		want finding.Severity // -1: not flagged
	}{
		{"x/y@v4", finding.Medium},
		{"x/y@main", finding.Medium},
		{"x/y", finding.Medium},
		{"x/y/sub/path@v1", finding.Medium},
		{"x/y@" + sha, -1},
		{"x/y@" + strings.ToUpper(sha), -1},
		{"x/y@" + sha[:39], finding.Medium},
		{"x/y@" + sha + "0", finding.Medium},
		{"x/y@" + strings.Repeat("g", 40), finding.Medium},
		{"./local", -1},
		{"./.github/actions/build", -1},
		{"actions/checkout@v4", finding.Low},
		{"Actions/Checkout@v4", finding.Low},
		{"github/codeql-action/init@v3", finding.Low},
		{"actions-rs/toolchain@v1", finding.Medium},
		{"docker://alpine:3.19", finding.Medium},
		{"docker://alpine", finding.Medium},
		{"docker://alpine@sha256:" + strings.Repeat("ab", 32), -1},
		{"docker://alpine:3.19@sha256:" + strings.Repeat("ab", 32), -1},
		{"docker://alpine@sha256:" + strings.Repeat("ab", 31), finding.Medium},
		{"x/v1@v1", finding.Medium},
	}
	for _, c := range cases {
		body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: " + c.uses + "\n"
		got := byID(runOne(t, body), "CI-002")
		if c.want < 0 {
			if len(got) != 0 {
				t.Errorf("%s: flagged %+v", c.uses, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Errorf("%s: %d findings", c.uses, len(got))
			continue
		}
		f := got[0]
		if f.Severity != c.want || f.Confidence != finding.Certain || f.Line != 6 || f.Evidence != c.uses ||
			f.ExplainKo != "설명2" || f.Fix != "수정2" {
			t.Errorf("%s: %+v", c.uses, f)
		}
	}
}

func TestCI002ReusableWorkflowJob(t *testing.T) {
	body := permsRead + `jobs:
  call:
    uses: org/repo/.github/workflows/build.yml@main
  pinned:
    uses: org/repo/.github/workflows/build.yml@` + strings.Repeat("0f", 20) + `
  local:
    uses: ./.github/workflows/other.yml
`
	got := byID(runOne(t, body), "CI-002")
	if len(got) != 1 || got[0].Line != lineOf(t, body, "@main") {
		t.Fatalf("%+v", got)
	}
}

func TestCI002SameActionTwiceKeepsBothLocations(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n      - uses: x/y@v1\n"
	got := byID(runOne(t, body), "CI-002")
	if len(got) != 2 || got[0].Fingerprint == got[1].Fingerprint || got[0].Line == got[1].Line {
		t.Fatalf("%+v", got)
	}
}

func TestCI003WriteAll(t *testing.T) {
	body := `permissions: write-all
jobs:
  a:
    permissions: write-all
    steps:
      - run: echo
  b:
    permissions:
      contents: read
    steps:
      - run: echo
  c:
    permissions: read-all
    steps:
      - run: echo
  d:
    permissions: {}
    steps:
      - run: echo
`
	got := byID(runOne(t, body), "CI-003")
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	for _, f := range got {
		if f.Severity != finding.High || f.Confidence != finding.Certain || f.ExplainKo != "설명3" || f.Fix != "수정3" {
			t.Errorf("%+v", f)
		}
	}
	if got[0].Line != 1 || got[1].Line != 4 || got[0].Fingerprint == got[1].Fingerprint {
		t.Errorf("%+v", got)
	}
}

func TestCI003ReadIsClean(t *testing.T) {
	for _, p := range []string{"permissions:\n  contents: read\n", "permissions: read-all\n", "permissions: {}\n"} {
		res := runOne(t, p+"jobs:\n  a:\n    steps:\n      - run: echo\n")
		if len(res.Findings) != 0 {
			t.Errorf("%q: %+v", p, res.Findings)
		}
	}
}

func TestCI003MissingPermissionsIsInfo(t *testing.T) {
	body := "on: push\njobs:\n  a:\n    steps:\n      - run: echo\n  b:\n    steps:\n      - run: echo\n"
	got := byID(runOne(t, body), "CI-003")
	if len(got) != 1 {
		t.Fatalf("%+v", got) // once per file, not per job
	}
	f := got[0]
	if f.Severity != finding.Info || f.Line != lineOf(t, body, "jobs:") || f.Location != ".github/workflows/w.yml" || f.ExplainKo != "설명3" {
		t.Fatalf("%+v", f)
	}
}

func TestCI003MissingPermissionsNeedsEveryJobToSetIt(t *testing.T) {
	all := "jobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - run: echo\n  b:\n    permissions: {}\n    steps:\n      - run: echo\n"
	if got := byID(runOne(t, all), "CI-003"); len(got) != 0 {
		t.Errorf("every job sets it: %+v", got)
	}
	some := "jobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - run: echo\n  b:\n    steps:\n      - run: echo\n"
	if got := byID(runOne(t, some), "CI-003"); len(got) != 1 || got[0].Severity != finding.Info {
		t.Errorf("one job lacks it: %+v", got)
	}
	top := "permissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - run: echo\n"
	if got := byID(runOne(t, top), "CI-003"); len(got) != 0 {
		t.Errorf("top level sets it: %+v", got)
	}
}

func TestCI003NoJobsNoInfo(t *testing.T) {
	if res := runOne(t, "name: x\non: push\n"); len(res.Findings) != 0 {
		t.Fatalf("%+v", res.Findings)
	}
}

const prHead = "${{ github.event.pull_request.head.sha }}"

func prt(on, ref string) string {
	step := "      - uses: actions/checkout@v4\n"
	if ref != "" {
		step += "        with:\n          ref: " + ref + "\n"
	}
	return on + permsRead + "jobs:\n  a:\n    steps:\n" + step
}

func TestCI004(t *testing.T) {
	cases := []struct {
		name string
		on   string
		ref  string
		want bool
	}{
		{"string form", "on: pull_request_target\n", prHead, true},
		{"list form", "on: [push, pull_request_target]\n", prHead, true},
		{"block list", "on:\n  - push\n  - pull_request_target\n", prHead, true},
		{"map form", "on:\n  pull_request_target:\n    types: [opened]\n", prHead, true},
		{"map form null", "on:\n  push:\n  pull_request_target:\n", prHead, true},
		{"quoted on", "\"on\": pull_request_target\n", prHead, true},
		{"head_ref", "on: pull_request_target\n", "${{ github.head_ref }}", true},
		{"head_ref spaces", "on: pull_request_target\n", "${{   github.head_ref   }}", true},
		{"head_ref bracket", "on: pull_request_target\n", "${{ github['head_ref'] }}", true},
		{"upper case", "on: pull_request_target\n", "${{ GitHub.Head_Ref }}", true},
		{"pull head ref", "on: pull_request_target\n", "${{ github.event.pull_request.head.ref }}", true},
		{"merge commit sha", "on: pull_request_target\n", "${{ github.event.pull_request.merge_commit_sha }}", true},
		{"refs/pull", "on: pull_request_target\n", "refs/pull/${{ github.event.number }}/merge", true},
		{"refs/pull from pr number", "on: pull_request_target\n", "refs/pull/${{ github.event.pull_request.number }}/head", true},
		{"no ref", "on: pull_request_target\n", "", false},
		{"base ref", "on: pull_request_target\n", "${{ github.base_ref }}", false},
		{"fixed ref", "on: pull_request_target\n", "main", false},
		{"refs/pull without event", "on: pull_request_target\n", "refs/pull/12/merge", false},
		{"other event", "on: pull_request\n", prHead, false},
		{"other event map", "on:\n  pull_request:\n  push:\n", prHead, false},
		{"similar event", "on: pull_request_target_x\n", prHead, false},
	}
	for _, c := range cases {
		body := prt(c.on, c.ref)
		got := byID(runOne(t, body), "CI-004")
		if !c.want {
			if len(got) != 0 {
				t.Errorf("%s: flagged %+v", c.name, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Errorf("%s: %d findings", c.name, len(got))
			continue
		}
		f := got[0]
		if f.Severity != finding.Critical || f.Line != lineOf(t, body, "uses: actions/checkout") || f.ExplainKo != "설명4" || f.Fix != "수정4" {
			t.Errorf("%s: %+v", c.name, f)
		}
	}
}

func TestCI004CheckoutForms(t *testing.T) {
	for _, uses := range []string{
		"actions/checkout@v4", "actions/checkout@main", "Actions/Checkout@v3",
		"actions/checkout@" + strings.Repeat("ab", 20), "actions/checkout",
	} {
		body := "on: pull_request_target\n" + permsRead + "jobs:\n  a:\n    steps:\n      - uses: " + uses + "\n        with:\n          ref: " + prHead + "\n"
		if got := byID(runOne(t, body), "CI-004"); len(got) != 1 {
			t.Errorf("%s: %+v", uses, got)
		}
	}
	body := "on: pull_request_target\n" + permsRead + "jobs:\n  a:\n    steps:\n      - uses: someone/checkout@v4\n        with:\n          ref: " + prHead + "\n"
	if got := byID(runOne(t, body), "CI-004"); len(got) != 0 {
		t.Errorf("another action: %+v", got)
	}
}

// ${{ }} text in the report is the file's own text, so only a fixed phrase
// is shown for the ref.
func TestCI004EvidenceIsFixedText(t *testing.T) {
	body := prt("on: pull_request_target\n", "${{ github.head_ref }}")
	f := byID(runOne(t, body), "CI-004")[0]
	if strings.Contains(f.Evidence, "${{") {
		t.Errorf("%q", f.Evidence)
	}
}

// In YAML 1.1 an unquoted on is the boolean true; yaml.v3 follows 1.2 for the
// key but the check does not depend on that.
func TestOnKeyForms(t *testing.T) {
	for _, on := range []string{"on", "On", "true", "\"on\""} {
		body := on + ": pull_request_target\n" + permsRead + "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: " + prHead + "\n"
		if got := byID(runOne(t, body), "CI-004"); len(got) != 1 {
			t.Errorf("key %s: %+v", on, got)
		}
	}
}

func TestBrokenYamlIsWarningAndOthersStillChecked(t *testing.T) {
	root := repo(t, map[string]string{
		"a-broken.yml": "jobs:\n  a: [unclosed\n    steps: {{\n",
		"b-good.yml":   permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@main\n",
	})
	res := run(t, root)
	if len(byID(res, "CI-002")) != 1 {
		t.Fatalf("%+v", res.Findings)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], ".github/workflows/a-broken.yml") {
		t.Fatalf("%+v", res.Warnings)
	}
}

func TestMultiDocument(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@one\n---\n" + permsRead + "jobs:\n  b:\n    steps:\n      - uses: x/y@two\n"
	got := byID(runOne(t, body), "CI-002")
	if len(got) != 2 || got[0].Line != lineOf(t, body, "@one") || got[1].Line != lineOf(t, body, "@two") {
		t.Fatalf("%+v", got)
	}
}

func TestMultiDocumentBrokenLaterDocKeepsEarlier(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@one\n---\njobs: [unclosed\n"
	res := runOne(t, body)
	if len(byID(res, "CI-002")) != 1 || len(res.Warnings) != 1 {
		t.Fatalf("%+v %+v", res.Findings, res.Warnings)
	}
}

func TestAliasedStepEnvAndPermissions(t *testing.T) {
	body := `x-env: &keys
  AWS_ACCESS_KEY_ID: ${{ secrets.A }}
x-step: &deploy
  uses: x/y@main
x-perm: &wide write-all
jobs:
  a:
    permissions: *wide
    env: *keys
    steps:
      - *deploy
  b:
    permissions: *wide
    steps:
      - *deploy
`
	res := runOne(t, body)
	if got := byID(res, "CI-001"); len(got) != 1 || got[0].Line != lineOf(t, body, "AWS_ACCESS_KEY_ID") {
		t.Errorf("CI-001 %+v", got)
	}
	if got := byID(res, "CI-002"); len(got) != 2 || got[0].Line != lineOf(t, body, "uses: x/y@main") || got[0].Fingerprint == got[1].Fingerprint {
		t.Errorf("CI-002 %+v", got)
	}
	wa := 0
	for _, f := range byID(res, "CI-003") {
		if f.Severity == finding.High {
			wa++
		}
	}
	if wa != 2 {
		t.Errorf("CI-003 %+v", byID(res, "CI-003"))
	}
}

func TestMergeKey(t *testing.T) {
	body := permsRead + `base: &base
  uses: x/y@main
jobs:
  a:
    steps:
      - <<: *base
        name: merged
`
	if got := byID(runOne(t, body), "CI-002"); len(got) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestAliasBombIsBounded(t *testing.T) {
	// 12 levels of 9 aliases each expand to 9^12 nodes if followed blindly
	var b strings.Builder
	nl := string(rune(10))
	b.WriteString("l0: &l0 [x, x, x, x, x, x, x, x, x]" + nl)
	for i := 1; i < 12; i++ {
		fmt.Fprintf(&b, "l%d: &l%d [", i, i)
		for j := 0; j < 9; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "*l%d", i-1)
		}
		b.WriteString("]" + nl)
	}
	b.WriteString(strings.Join([]string{"on: *l11", "jobs:", "  a:", "    steps:", "      - uses: x/y@main", ""}, nl))
	done := make(chan checker.Result, 1)
	root := repo(t, map[string]string{"w.yml": b.String()})
	go func() { done <- run(t, root) }()
	select {
	case res := <-done:
		if len(byID(res, "CI-002")) != 1 {
			t.Fatalf("%+v", res)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("alias expansion did not stop")
	}
}

func TestSelfReferencingNodesAreBounded(t *testing.T) {
	// an anchor used inside itself is rejected by the parser or ignored; neither may hang
	body := "a: &a\n  b: *a\njobs:\n  a:\n    steps:\n      - uses: x/y@main\n"
	done := make(chan struct{})
	root := repo(t, map[string]string{"w.yml": body})
	go func() { defer close(done); run(t, root) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("hang")
	}
}

func TestHugeFileIsWarnedNotParsed(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@main\n# " + strings.Repeat("x", 1<<20) + "\n"
	res := runOne(t, body)
	if len(res.Findings) != 1 || res.Findings[0].ID != "CI-005" || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], ".github/workflows/w.yml") {
		t.Fatalf("%+v", res)
	}
}

func TestSymlinkedWorkflowIsNotFollowed(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "evil.yml")
	os.WriteFile(target, []byte("jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"), 0o644)
	root := repo(t, map[string]string{"ok.yml": permsRead + "jobs:\n  a:\n    steps:\n      - run: echo\n"})
	if err := os.Symlink(target, filepath.Join(root, ".github", "workflows", "link.yml")); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	res := run(t, root)
	if len(byID(res, "CI-002")) != 0 || len(byID(res, "CI-005")) != 1 {
		t.Fatalf("followed the link: %+v", res.Findings)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], ".github/workflows/link.yml") {
		t.Fatalf("%+v", res.Warnings)
	}
}

func TestSymlinkedWorkflowFolderIsNotFollowed(t *testing.T) {
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "w.yml"), []byte("jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"), 0o644)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".github"), 0o755)
	if err := os.Symlink(outside, filepath.Join(root, ".github", "workflows")); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	res := run(t, root)
	if len(byID(res, "CI-005")) != 1 || len(byID(res, "CI-002")) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], ".github/workflows") {
		t.Fatalf("%+v", res)
	}
}

func TestUntrustedGivesSameResult(t *testing.T) {
	root := repo(t, map[string]string{"w.yml": "jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"})
	a := run(t, root)
	b, err := New(testData).Run(context.Background(), checker.Target{Root: root, Untrusted: true, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		t.Fatalf("%s\n%s", x, y)
	}
}

func TestNilDataGivesEmptyTexts(t *testing.T) {
	root := repo(t, map[string]string{"w.yml": "jobs:\n  a:\n    steps:\n      - uses: x/y@main\n"})
	res, err := New(nil).Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) == 0 || res.Findings[0].ExplainKo != "" || res.Findings[0].Fix != "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := repo(t, map[string]string{"w.yml": "jobs: {}\n"})
	if _, err := New(testData).Run(ctx, checker.Target{Root: root}); err == nil {
		t.Fatal("want context error")
	}
}

func TestTextInEvidenceIsCleaned(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n      - uses: \"x/y@v1\\u202e`evil`\\u0007\"\n"
	got := byID(runOne(t, body), "CI-002")
	if len(got) != 1 || strings.ContainsAny(got[0].Evidence, "`\u202e\a") {
		t.Fatalf("%+v", got)
	}
}

func TestCI005UnreadableFiles(t *testing.T) {
	big := permsRead + "jobs:\n  a:\n    steps:\n      - uses: x/y@main\n# " + strings.Repeat("x", 1<<20) + "\n"
	res := runOne(t, big)
	got := byID(res, "CI-005")
	if len(got) != 1 {
		t.Fatalf("%+v", res.Findings)
	}
	f := got[0]
	if f.Severity != finding.Medium || f.Confidence != finding.Suspect || f.Location != ".github/workflows/w.yml" ||
		f.ExplainKo != "설명5" || f.Fix != "수정5" || f.Fingerprint == "" || f.Source != "cicd" || f.Title == "" {
		t.Fatalf("%+v", f)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warning kept: %+v", res.Warnings)
	}
}

func TestCI005NonRegularWorkflow(t *testing.T) {
	root := repo(t, map[string]string{"ok.yml": permsRead + "jobs:\n  a:\n    steps:\n      - run: echo\n"})
	// a folder named like a workflow is skipped (GitHub reads only files)
	os.MkdirAll(filepath.Join(root, ".github", "workflows", "dir.yml"), 0o755)
	if res := run(t, root); len(res.Findings) != 0 {
		t.Fatalf("%+v", res.Findings)
	}
}

func floodSteps(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("      - uses: a/b@main\n")
	}
	return b.String()
}

func TestFindingCapKeepsCritical(t *testing.T) {
	body := "on: pull_request_target\n" + permsRead + "jobs:\n  flood:\n    steps:\n" + floodSteps(500) +
		"  last:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: " + prHead + "\n"
	res := runOne(t, body)
	if len(res.Findings) != 201 || len(byID(res, "CI-005")) != 1 || len(byID(res, "CI-004")) != 1 || len(byID(res, "CI-002")) != 199 {
		t.Fatalf("total %d CI-002 %d CI-004 %d CI-005 %d", len(res.Findings), len(byID(res, "CI-002")), len(byID(res, "CI-004")), len(byID(res, "CI-005")))
	}
	if c := byID(res, "CI-005")[0]; c.Severity != finding.Medium || c.Confidence != finding.Suspect {
		t.Fatalf("%+v", c)
	}
}

func TestFindingCapExactlyAtLimit(t *testing.T) {
	body := permsRead + "jobs:\n  a:\n    steps:\n" + floodSteps(200)
	res := runOne(t, body)
	if len(res.Findings) != 200 || len(byID(res, "CI-005")) != 0 {
		t.Fatalf("%d", len(res.Findings))
	}
}

func TestFindingCapOnAliasFlood(t *testing.T) {
	var b strings.Builder
	b.WriteString(permsRead + "x: &steps\n")
	b.WriteString("jobs:\n  base: &job\n    steps: &s\n" + floodSteps(300))
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "  j%d: *job\n", i)
	}
	res := runOne(t, b.String())
	if len(res.Findings) > 201 || len(byID(res, "CI-005")) != 1 {
		t.Fatalf("%d findings", len(res.Findings))
	}
}

func TestCI001ContainerAndServicesEnv(t *testing.T) {
	body := permsRead + `jobs:
  a:
    container:
      image: example/img:1
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.A }}
    services:
      db:
        image: example/db:1
        env:
          AWS_SECRET_ACCESS_KEY: ${{ secrets.B }}
      cache: example/cache:1
    steps:
      - run: echo
  b:
    container: example/img:1
    steps:
      - run: echo
`
	got := byID(runOne(t, body), "CI-001")
	if len(got) != 2 || got[0].Line != lineOf(t, body, "AWS_ACCESS_KEY_ID") || got[1].Line != lineOf(t, body, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got[0].Evidence, "container") || !strings.Contains(got[1].Evidence, "db") {
		t.Errorf("%q %q", got[0].Evidence, got[1].Evidence)
	}
}

func TestCI001ValueKinds(t *testing.T) {
	cases := []struct {
		value string
		sev   finding.Severity
		conf  finding.Confidence
	}{
		{"${{ secrets.X }}", finding.High, finding.Certain},
		{"${{ SECRETS.X }}", finding.High, finding.Certain},
		{"literal" + "Value123", finding.High, finding.Certain},
		{"prefix-${{ secrets.X }}-suffix", finding.High, finding.Certain},
		{"${{ steps.creds.outputs.key }}", finding.Medium, finding.Suspect},
		{"${{ env.OTHER }}", finding.Medium, finding.Suspect},
		{"${{ vars.X }}", finding.Medium, finding.Suspect},
		{"${{ steps.a.outputs.k || secrets.FALLBACK }}", finding.High, finding.Certain},
	}
	for _, c := range cases {
		body := permsRead + "jobs:\n  a:\n    env:\n      AWS_ACCESS_KEY_ID: " + c.value + "\n    steps:\n      - run: echo\n"
		res := runOne(t, body)
		got := byID(res, "CI-001")
		if len(got) != 1 || got[0].Severity != c.sev || got[0].Confidence != c.conf {
			t.Errorf("%s: %+v", c.value, got)
			continue
		}
		all, _ := json.Marshal(res)
		if strings.Contains(string(all), c.value) || strings.Contains(string(all), "steps.creds") {
			t.Errorf("%s: value in result", c.value)
		}
	}
}
