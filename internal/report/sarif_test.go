package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// validateSARIF checks data against the OASIS SARIF 2.1.0 schema stored in
// testdata. It never touches the network.
func validateSARIF(t *testing.T, data []byte) {
	t.Helper()
	f, err := os.Open("../../testdata/sarif/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	const id = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
	if err := c.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("schema validation failed:\n%v", err)
	}
}

type obj = map[string]any

// sarifOf renders r, validates it against the schema and returns the parsed run.
func sarifOf(t *testing.T, r Report) (run obj, raw []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	validateSARIF(t, buf.Bytes())
	var log obj
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	runs := log["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	return runs[0].(obj), buf.Bytes()
}

func rulesOf(run obj) []obj {
	var out []obj
	for _, x := range run["tool"].(obj)["driver"].(obj)["rules"].([]any) {
		out = append(out, x.(obj))
	}
	return out
}

func resultsOf(run obj) []obj {
	var out []obj
	for _, x := range run["results"].([]any) {
		out = append(out, x.(obj))
	}
	return out
}

func props(o obj) obj { p, _ := o["properties"].(obj); return p }

func hasTag(o obj, tag string) bool {
	tags, _ := props(o)["tags"].([]any)
	for _, x := range tags {
		if x == tag {
			return true
		}
	}
	return false
}

func oneFinding(f finding.Finding) Report {
	if f.Fingerprint == "" {
		f.Fingerprint = "ffff000011112222"
	}
	if f.Title == "" {
		f.Title = "제목"
	}
	if f.Location == "" {
		f.Location = "a.py"
	}
	if f.Confidence == "" {
		f.Confidence = finding.Certain
	}
	return Report{Target: "x", ToolVersion: "v0.1.0", Findings: []finding.Finding{f}}
}

func TestSARIFGolden(t *testing.T) {
	r := fixedReport()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	const path = "../../testdata/report/golden.sarif"
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(want) {
		t.Errorf("sarif differs from golden (run with -update):\n%s", buf.String())
	}
	validateSARIF(t, want)
}

func TestSARIFDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := WriteSARIF(&a, fixedReport()); err != nil {
		t.Fatal(err)
	}
	if err := WriteSARIF(&b, fixedReport()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("two renders differ")
	}
}

func TestSARIFEmptyResults(t *testing.T) {
	run, raw := sarifOf(t, Report{Target: "x", ToolVersion: "v0.1.0"})
	if !strings.Contains(string(raw), `"results": []`) || !strings.Contains(string(raw), `"rules": []`) {
		t.Errorf("results and rules must be [] not null:\n%s", raw)
	}
	if len(resultsOf(run)) != 0 || len(rulesOf(run)) != 0 {
		t.Error("expected no results or rules")
	}
}

func TestSARIFLevels(t *testing.T) {
	want := map[finding.Severity]string{
		finding.Critical: "error", finding.High: "error", finding.Medium: "warning",
		finding.Low: "note", finding.Info: "note",
	}
	for sev, level := range want {
		run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Severity: sev}))
		if got := resultsOf(run)[0]["level"]; got != level {
			t.Errorf("%v: result level = %v, want %s", sev, got, level)
		}
		dc := rulesOf(run)[0]["defaultConfiguration"].(obj)["level"]
		if dc != level {
			t.Errorf("%v: rule level = %v, want %s", sev, dc, level)
		}
	}
}

func TestSARIFSecuritySeverity(t *testing.T) {
	want := map[finding.Severity]string{
		finding.Critical: "9.5", finding.High: "8.0", finding.Medium: "5.5", finding.Low: "2.0",
	}
	for sev, score := range want {
		run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Severity: sev}))
		rule := rulesOf(run)[0]
		if got := props(rule)["security-severity"]; got != score {
			t.Errorf("%v: security-severity = %v, want %s", sev, got, score)
		}
		if !hasTag(rule, "security") {
			t.Errorf("%v: tags lack security: %v", sev, props(rule)["tags"])
		}
	}
	run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Severity: finding.Info}))
	rule := rulesOf(run)[0]
	if _, ok := props(rule)["security-severity"]; ok {
		t.Error("info must not have security-severity")
	}
	if !hasTag(rule, "security") {
		t.Error("info rule still carries the security tag")
	}
}

func TestSARIFPartialFingerprint(t *testing.T) {
	run, _ := sarifOf(t, fixedReport())
	fs := canonicalFindings(fixedReport().Findings)
	for i, res := range resultsOf(run) {
		if fs[i].Fingerprint == "" {
			if _, ok := res["partialFingerprints"]; ok {
				t.Errorf("result %d: empty fingerprint must be omitted", i)
			}
			continue
		}
		got := res["partialFingerprints"].(obj)["adkFingerprint/v1"]
		if got != fs[i].Fingerprint {
			t.Errorf("result %d fingerprint = %v, want %s", i, got, fs[i].Fingerprint)
		}
	}
}

func secretsReport(fs ...finding.Finding) Report {
	r := Report{Target: "x", ToolVersion: "v0.1.0"}
	for i, f := range fs {
		f.Source = "secrets"
		f.Location = "config.py"
		f.Title = "키"
		f.Fingerprint = strings.Repeat(string(rune('a'+i)), 16)
		r.Findings = append(r.Findings, f)
	}
	return r
}

func TestSARIFSameIDDifferentKindSplit(t *testing.T) {
	r := secretsReport(
		finding.Finding{ID: "SECRET-x", Kind: "secret-current", Severity: finding.High, Confidence: finding.Certain},
		finding.Finding{ID: "SECRET-x", Kind: "secret-history", Severity: finding.Medium, Confidence: finding.Certain},
	)
	run, _ := sarifOf(t, r)
	rules := rulesOf(run)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	res := resultsOf(run)
	if res[0]["ruleId"] != "SECRET-x/secret-current" || res[1]["ruleId"] != "SECRET-x/secret-history" {
		t.Errorf("ruleIds = %v, %v", res[0]["ruleId"], res[1]["ruleId"])
	}
	if props(rules[0])["security-severity"] != "8.0" || props(rules[1])["security-severity"] != "5.5" {
		t.Errorf("severities = %v, %v", props(rules[0])["security-severity"], props(rules[1])["security-severity"])
	}
	for i, x := range res {
		if int(x["ruleIndex"].(float64)) != i {
			t.Errorf("result %d ruleIndex = %v", i, x["ruleIndex"])
		}
	}
}

func TestSARIFMixedSeverityUsesHighest(t *testing.T) {
	r := Report{Target: "x", ToolVersion: "v0.1.0", Findings: []finding.Finding{
		{ID: "KR-1", Source: "rules", Severity: finding.High, Confidence: finding.Certain, Location: "a.py", Title: "a", Fingerprint: "aaaaaaaaaaaaaaaa"},
		{ID: "KR-1", Source: "rules", Severity: finding.Low, Confidence: finding.Certain, Location: "b.py", Title: "b", Fingerprint: "bbbbbbbbbbbbbbbb"},
	}}
	run, _ := sarifOf(t, r)
	rules := rulesOf(run)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if props(rules[0])["security-severity"] != "8.0" {
		t.Errorf("security-severity = %v, want 8.0", props(rules[0])["security-severity"])
	}
	res := resultsOf(run)
	if res[0]["level"] != "error" || res[1]["level"] != "note" {
		t.Errorf("levels = %v, %v", res[0]["level"], res[1]["level"])
	}
}

func TestSARIFPrecision(t *testing.T) {
	mk := func(id, src string, conf ...finding.Confidence) Report {
		r := Report{Target: "x", ToolVersion: "v0.1.0"}
		for i, c := range conf {
			r.Findings = append(r.Findings, finding.Finding{ID: id, Kind: "secret-current", Source: src, Severity: finding.High, Confidence: c,
				Location: "a.py", Title: "t", Fingerprint: strings.Repeat(string(rune('a'+i)), 16)})
		}
		return r
	}
	cases := []struct {
		name string
		r    Report
		want string
	}{
		{"certain", mk("R-1", "rules", finding.Certain), "high"},
		{"suspect", mk("R-1", "rules", finding.Suspect), "medium"},
		{"mixed", mk("R-1", "rules", finding.Certain, finding.Suspect), "medium"},
		{"secrets", mk("SECRET-x", "secrets", finding.Certain), "medium"},
	}
	for _, c := range cases {
		run, _ := sarifOf(t, c.r)
		if got := props(rulesOf(run)[0])["precision"]; got != c.want {
			t.Errorf("%s: precision = %v, want %s", c.name, got, c.want)
		}
	}
	run, _ := sarifOf(t, mk("R-1", "rules", finding.Certain, finding.Suspect))
	res := resultsOf(run)
	if props(res[0])["confidence"] != "certain" || props(res[1])["confidence"] != "suspect" {
		t.Errorf("result confidences = %v, %v", props(res[0])["confidence"], props(res[1])["confidence"])
	}
}

func TestSARIFExploited(t *testing.T) {
	run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "DEP-CVE-1", Source: "deps", Severity: finding.Critical, Exploited: true, Title: "취약한 라이브러리"}))
	res := resultsOf(run)[0]
	text := res["message"].(obj)["text"].(string)
	if !strings.HasPrefix(text, "[실제 공격 중] 취약한 라이브러리") {
		t.Errorf("message = %q", text)
	}
	if !hasTag(res, "actively-exploited") || !hasTag(rulesOf(run)[0], "actively-exploited") {
		t.Error("actively-exploited tag missing on result or rule")
	}
	run, _ = sarifOf(t, oneFinding(finding.Finding{ID: "DEP-CVE-1", Source: "deps", Severity: finding.High}))
	if hasTag(resultsOf(run)[0], "actively-exploited") || hasTag(rulesOf(run)[0], "actively-exploited") {
		t.Error("tag must be absent when not exploited")
	}
}

func TestSARIFKoreanMessage(t *testing.T) {
	r := oneFinding(finding.Finding{
		ID: "KR-PAY-002", Source: "rules", Severity: finding.High, Title: "포트원 웹훅 검증 누락",
		Evidence: `secret = "AB****"`, Fix: "Webhook.verify를 호출하세요.", ExplainKo: "서명을 확인하지 않으면 위험합니다.",
		Mappings: []finding.Mapping{{ID: "ISMSP-2.10.4", ReviewStatus: "draft"}},
	})
	run, _ := sarifOf(t, r)
	text := resultsOf(run)[0]["message"].(obj)["text"].(string)
	for _, want := range []string{"포트원 웹훅 검증 누락", "근거: secret = \"AB****\"", "수정 방법: Webhook.verify를 호출하세요.", "국내 기준: ISMSP-2.10.4 (검수 전)"} {
		if !strings.Contains(text, want) {
			t.Errorf("message lacks %q:\n%s", want, text)
		}
	}
	help := rulesOf(run)[0]["help"].(obj)
	for _, k := range []string{"text", "markdown"} {
		s := help[k].(string)
		if !strings.Contains(s, "서명을 확인하지 않으면 위험합니다.") || !strings.Contains(s, Disclaimer) {
			t.Errorf("help.%s = %q", k, s)
		}
	}
	// Empty items are dropped.
	run, _ = sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Title: "제목만"}))
	text = resultsOf(run)[0]["message"].(obj)["text"].(string)
	if text != "제목만" {
		t.Errorf("message = %q, want title only", text)
	}
}

func TestSARIFLongTextTruncated(t *testing.T) {
	long := strings.Repeat("가", maxMessageRunes*2)
	run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Severity: finding.High, Fix: long, ExplainKo: strings.Repeat("나", maxHelpRunes*2)}))
	text := resultsOf(run)[0]["message"].(obj)["text"].(string)
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > maxMessageRunes {
		t.Errorf("message runes = %d (valid=%v), max %d", utf8.RuneCountInString(text), utf8.ValidString(text), maxMessageRunes)
	}
	if !strings.HasSuffix(text, "전체 내용은 리포트 참고") {
		t.Errorf("message tail = %q", text[len(text)-60:])
	}
	help := rulesOf(run)[0]["help"].(obj)["text"].(string)
	if !utf8.ValidString(help) || utf8.RuneCountInString(help) > maxHelpRunes {
		t.Errorf("help runes = %d", utf8.RuneCountInString(help))
	}
	if !strings.Contains(help, "전체 내용은 리포트 참고") || !strings.HasSuffix(help, Disclaimer) {
		t.Error("help must keep the disclaimer and note the cut")
	}
	// GitHub caps shortDescription at 1024 characters.
	run, _ = sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Title: strings.Repeat("다", 3000)}))
	sd := rulesOf(run)[0]["shortDescription"].(obj)["text"].(string)
	if n := utf8.RuneCountInString(sd); n > 1024 {
		t.Errorf("shortDescription runes = %d", n)
	}
}

func locationOfResult(res obj) obj {
	return res["locations"].([]any)[0].(obj)["physicalLocation"].(obj)
}

func TestSARIFRepoPrefix(t *testing.T) {
	r := oneFinding(finding.Finding{ID: "X-1", Source: "rules", Location: "src/a.py"})
	r.RepoPrefix = "apps/web/"
	run, _ := sarifOf(t, r)
	art := locationOfResult(resultsOf(run)[0])["artifactLocation"].(obj)
	if art["uri"] != "apps/web/src/a.py" || art["uriBaseId"] != "%SRCROOT%" {
		t.Errorf("artifactLocation = %v", art)
	}
	r.RepoPrefix = ""
	run, _ = sarifOf(t, r)
	if got := locationOfResult(resultsOf(run)[0])["artifactLocation"].(obj)["uri"]; got != "src/a.py" {
		t.Errorf("uri = %v", got)
	}
}

func TestSARIFEncodesPath(t *testing.T) {
	r := oneFinding(finding.Finding{ID: "X-1", Source: "rules", Location: "소스 폴더/앱.py"})
	run, _ := sarifOf(t, r)
	got := locationOfResult(resultsOf(run)[0])["artifactLocation"].(obj)["uri"].(string)
	want := "%EC%86%8C%EC%8A%A4%20%ED%8F%B4%EB%8D%94/%EC%95%B1.py"
	if got != want {
		t.Errorf("uri = %q, want %q", got, want)
	}
}

func TestSARIFNoRegionWithoutLine(t *testing.T) {
	run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Line: 0}))
	if _, ok := locationOfResult(resultsOf(run)[0])["region"]; ok {
		t.Error("region must be absent when Line is 0")
	}
	run, _ = sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Line: 3}))
	region := locationOfResult(resultsOf(run)[0])["region"].(obj)
	if region["startLine"] != float64(3) {
		t.Errorf("region = %v", region)
	}
}

func TestSARIFNotifications(t *testing.T) {
	root := "/home/me/proj"
	r := Report{Target: "x", ToolVersion: "v0.1.0", ScanRoot: root, Checks: []checker.CheckStatus{
		{Name: "rules", Status: checker.StatusOK},
		{Name: "secrets", Status: checker.StatusOK, Warnings: []string{"git 기록 없음: " + root + "/.git"}},
		{Name: "deps", Status: checker.StatusFailed, Error: "OSV 조회 실패 " + root + "/package-lock.json"},
		{Name: "supabase", Status: checker.StatusSkipped, Error: "skipped: 설정 없음"},
	}}
	run, raw := sarifOf(t, r)
	if strings.Contains(string(raw), root) {
		t.Errorf("ScanRoot leaked:\n%s", raw)
	}
	inv := run["invocations"].([]any)[0].(obj)
	if inv["executionSuccessful"] != false {
		t.Errorf("executionSuccessful = %v, want false", inv["executionSuccessful"])
	}
	got := map[string]string{}
	for _, x := range inv["toolExecutionNotifications"].([]any) {
		n := x.(obj)
		got[n["message"].(obj)["text"].(string)] = n["level"].(string)
	}
	want := map[string]string{
		"secrets: git 기록 없음: ./.git":               "warning",
		"deps (실패): OSV 조회 실패 ./package-lock.json": "error",
		"supabase (건너뜀): skipped: 설정 없음":           "warning",
	}
	if len(got) != len(want) {
		t.Errorf("notifications = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("notification %q level = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}

	// Skipped checks and warnings alone do not fail the execution.
	r.Checks = []checker.CheckStatus{{Name: "supabase", Status: checker.StatusSkipped, Error: "skipped: 없음"}}
	run, _ = sarifOf(t, r)
	if run["invocations"].([]any)[0].(obj)["executionSuccessful"] != true {
		t.Error("skipped only must keep executionSuccessful true")
	}
}

func TestSARIFRunProperties(t *testing.T) {
	r := fixedReport()
	r.GitDirty = "dirty"
	run, _ := sarifOf(t, r)
	p := props(run)
	if p["gitCommit"] != r.GitCommit || p["gitDirty"] != "dirty" {
		t.Errorf("properties = %v", p)
	}
	if _, ok := run["versionControlProvenance"]; ok {
		t.Error("versionControlProvenance must be absent")
	}
	r.GitDirty = ""
	run, _ = sarifOf(t, r)
	if props(run)["gitDirty"] != DirtyUnknown {
		t.Errorf("empty GitDirty should be %q, got %v", DirtyUnknown, props(run)["gitDirty"])
	}
}

func TestSARIFExcludesIgnored(t *testing.T) {
	r := fixedReport()
	r.IgnoredFindings = []finding.Finding{{ID: "HIDDEN-1", Source: "rules", Severity: finding.High, Location: "h.py", Fingerprint: "deadbeefdeadbeef", Title: "숨김"}}
	_, raw := sarifOf(t, r)
	if strings.Contains(string(raw), "deadbeefdeadbeef") || strings.Contains(string(raw), "HIDDEN-1") {
		t.Error("ignored finding appeared in SARIF")
	}
	if strings.Contains(string(raw), "suppressions") {
		t.Error("suppressions must not be used")
	}
}

func TestSARIFToolDriver(t *testing.T) {
	run, raw := sarifOf(t, fixedReport())
	driver := run["tool"].(obj)["driver"].(obj)
	if driver["name"] != "adk" || driver["version"] != "v0.1.0" || driver["informationUri"] != "https://github.com/iimmuunnee/ai-defense-kit" {
		t.Errorf("driver = %v", driver)
	}
	if _, ok := driver["semanticVersion"]; ok {
		t.Error("semanticVersion must be absent")
	}
	if !strings.Contains(string(raw), `"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"`) {
		t.Error("$schema missing")
	}
}

func TestSARIFPrimaryLocationLineHash(t *testing.T) {
	mk := func(line int, fp string) finding.Finding {
		return finding.Finding{ID: "X-1", Source: "rules", Severity: finding.High, Confidence: finding.Certain,
			Location: "a.py", Line: line, Title: "t", Fingerprint: fp}
	}
	r := Report{Target: "x", ToolVersion: "v0.1.0", Findings: []finding.Finding{
		mk(1, "aaaa"), mk(2, "aaaa"), mk(3, "bbbb"), mk(4, ""),
	}}
	run, _ := sarifOf(t, r)
	res := resultsOf(run)
	hash := func(i int) any { m, _ := res[i]["partialFingerprints"].(obj); return m["primaryLocationLineHash"] }
	if hash(0) != "aaaa:1" || hash(1) != "aaaa:2" || hash(2) != "bbbb:1" {
		t.Errorf("hashes = %v %v %v", hash(0), hash(1), hash(2))
	}
	if _, ok := res[3]["partialFingerprints"]; ok {
		t.Error("empty fingerprint must omit both keys")
	}
	// A moved line keeps the same value.
	r2 := Report{Target: "x", ToolVersion: "v0.1.0", Findings: []finding.Finding{mk(99, "aaaa")}}
	run2, _ := sarifOf(t, r2)
	if got := resultsOf(run2)[0]["partialFingerprints"].(obj)["primaryLocationLineHash"]; got != "aaaa:1" {
		t.Errorf("hash after line move = %v", got)
	}
}

func TestSARIFNoPathLeak(t *testing.T) {
	root, priv := "/home/me/proj", "/home/me/secret-dir"
	f := finding.Finding{ID: "X-1", Source: "rules", Severity: finding.High, Confidence: finding.Certain, Fingerprint: "ffff",
		Title: "제목 " + root + "/t.py " + priv, ExplainKo: "설명 " + root + " " + priv,
		Fix: "고치기 " + root + "/f " + priv, Evidence: "근거 " + root + "/e " + priv,
		Location: root + "/src/a.py"}
	r := Report{Target: "x", ToolVersion: "v0.1.0", ScanRoot: root, PrivatePaths: []string{priv}, Findings: []finding.Finding{f}}
	run, raw := sarifOf(t, r)
	if strings.Contains(string(raw), root) || strings.Contains(string(raw), priv) {
		t.Errorf("path leaked:\n%s", raw)
	}
	uri := locationOfResult(resultsOf(run)[0])["artifactLocation"].(obj)["uri"]
	if uri != "src/a.py" {
		t.Errorf("uri = %v, want src/a.py", uri)
	}
	// A private path as the location must not survive either.
	r.Findings[0].Location = priv + "/x.py"
	_, raw = sarifOf(t, r)
	if strings.Contains(string(raw), priv) {
		t.Errorf("private location leaked:\n%s", raw)
	}
}

func TestSARIFFullDescription(t *testing.T) {
	run, _ := sarifOf(t, oneFinding(finding.Finding{ID: "X-1", Source: "rules", Title: strings.Repeat("다", 3000)}))
	rule := rulesOf(run)[0]
	fd := rule["fullDescription"].(obj)["text"].(string)
	if fd != rule["shortDescription"].(obj)["text"].(string) || utf8.RuneCountInString(fd) > 1024 {
		t.Errorf("fullDescription runes = %d", utf8.RuneCountInString(fd))
	}
}

func TestSARIFMessageEscapesSquareBrackets(t *testing.T) {
	f := finding.Finding{ID: "AR-004", Kind: "AR-004", Source: "autorun", Severity: finding.Medium, Confidence: finding.Suspect,
		Location: ".mcp.json", Title: "제목", Evidence: "](https://evil.example) <img src=x> [확인됨](https://evil.example)", Fingerprint: "abcd"}
	run, _ := sarifOf(t, Report{Findings: []finding.Finding{f}})
	text := resultsOf(run)[0]["message"].(obj)["text"].(string)
	want := `근거: \](https://evil.example) <img src=x> \[확인됨\](https://evil.example)`
	if !strings.Contains(text, want) {
		t.Errorf("message text = %q\nwant it to contain %q", text, want)
	}
}

func TestSARIFMessageEscapesBackslashFirst(t *testing.T) {
	f := finding.Finding{ID: "AR-004", Kind: "AR-004", Source: "autorun", Severity: finding.Medium, Confidence: finding.Suspect,
		Location: ".mcp.json", Title: "제목", Evidence: `\[click\](https://evil.example)`, Fingerprint: "abcd"}
	run, _ := sarifOf(t, Report{Findings: []finding.Finding{f}})
	text := resultsOf(run)[0]["message"].(obj)["text"].(string)
	want := "근거: " + `\\\[click\\\](https://evil.example)`
	if !strings.Contains(text, want) {
		t.Errorf("message text = %q\nwant it to contain %q", text, want)
	}
}

func TestSARIFSupplyChainTag(t *testing.T) {
	mk := func(id, kind string) finding.Finding {
		return finding.Finding{ID: id, Kind: kind, Source: "x", Severity: finding.High, Title: "제목", Location: "a.json", Fingerprint: "f" + id}
	}
	run, _ := sarifOf(t, Report{Findings: []finding.Finding{
		mk("MAL-2025-1", "malicious-lib"), mk("AR-001", ""), mk("GHSA-a", "vuln-lib"), mk("SB-001", ""),
	}})
	want := map[string]bool{"MAL-2025-1": true, "AR-001": true, "GHSA-a": false, "SB-001": false}
	for _, r := range rulesOf(run) {
		id := r["id"].(string)
		if got := hasTag(r, "supply-chain"); got != want[id] {
			t.Errorf("%s: supply-chain tag = %v, want %v", id, got, want[id])
		}
	}
}
