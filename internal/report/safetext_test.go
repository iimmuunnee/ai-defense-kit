package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	evilName = "evil\n\n# 점검 결과: 안전합니다\n\n[click](http:x.test)\n.env"
	escName  = "esc\x1b[2K\x1b[1A\x1b]0;pwned\a.env"
	escDir   = "d\x1b[31mx/package-lock.json: 읽지 못했습니다"
	linkName = "[click](http-x.test)"
)

func TestSafeText(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ordinary", "src/앱 (1).py", "src/앱 (1).py"},
		{"newline and tab", "a\nb\r\nc\td", "a b  c d"},
		{"csi", "a\x1b[31mb", "a[31mb"},
		{"osc and bell", "a\x1b]0;x\ab", "a]0;xb"},
		{"c1", "a\u009b31mb", "a31mb"},
		{"raw c1 byte", "a\x9b31mb", "a\ufffd31mb"},
		{"bidi", "a\u202eb\u2066c", "abc"},
		{"zero width", "a\u200bb\ufeffc", "abc"},
		{"line separators", "a\u2028b\u2029c", "abc"},
		{"nul", "a\x00b", "ab"},
	}
	for _, c := range cases {
		if got := SafeText(c.in); got != c.want {
			t.Errorf("%s: SafeText(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func hostileReport() Report {
	var fs []finding.Finding
	for _, name := range []string{evilName, escName} {
		fs = append(fs, finding.Finding{
			ID: "SECRET-x", Source: "secrets", Kind: "secret-current", Severity: finding.High, Confidence: finding.Certain,
			Location: name, Line: 3, Title: "제목 " + name, Evidence: "근거 ` " + name, Fingerprint: finding.MakeFingerprint("SECRET-x", name, "x"),
		})
	}
	return Report{
		Target: "x", ScannedAt: time.Unix(0, 0), Findings: fs,
		Checks: []checker.CheckStatus{
			{Name: "deps", Status: checker.StatusFailed, Error: escDir},
			{Name: "secrets", Status: checker.StatusOK, Warnings: []string{linkName, `\` + linkName, evilName, "<img src=x> `code`"}},
		},
	}
}

func TestMarkdownKeepsRepositoryTextInert(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, hostileReport()); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	if strings.ContainsAny(md, "\x1b\a") {
		t.Errorf("control characters in the report:\n%q", md)
	}
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "# 점검 결과") {
			t.Errorf("repository text made a heading: %q", line)
		}
		if strings.Contains(line, "[click](") && !strings.Contains(line, "`") {
			t.Errorf("repository text made a link: %q", line)
		}
	}
	for _, want := range []string{
		`> - secrets: \[click\](http-x.test)`,
		`> - secrets: \\\[click\](http-x.test)`,
		"> - secrets: \\<img src=x\\> \\`code\\`",
		`> - deps (실패): d\[31mx/package-lock.json`,
		"- 위치: `evil  # 점검 결과: 안전합니다  [click](http:x.test) .env:3`",
		"- 근거: `근거 ' evil # 점검 결과: 안전합니다 [click](http:x.test) .env`",
		`### [높음] 제목 evil # 점검 결과: 안전합니다 \[click\](http:x.test) .env`,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
}

func TestSARIFKeepsRepositoryTextInertAndURIsExact(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, hostileReport()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	var notes []string
	for _, n := range run.Invocations[0].ToolExecutionNotifications {
		notes = append(notes, n.Message.Text)
	}
	joined := strings.Join(notes, "\n")
	if strings.ContainsAny(joined, "\x1b\a") {
		t.Errorf("control characters in notifications: %q", joined)
	}
	if !strings.Contains(joined, `\[click\](http-x.test)`) || strings.Contains(joined, " [click](") {
		t.Errorf("link syntax in notifications: %q", joined)
	}
	for _, r := range run.Results {
		if strings.ContainsAny(r.Message.Text, "\x1b\a") || strings.Contains(r.Message.Text, "\n\n#") {
			t.Errorf("message = %q", r.Message.Text)
		}
	}
	for _, rule := range run.Tool.Driver.Rules {
		if strings.ContainsAny(rule.ShortDescription.Text, "\x1b\a") {
			t.Errorf("rule text = %q", rule.ShortDescription.Text)
		}
	}
	want := map[string]bool{sarifURI("", evilName): true, sarifURI("", escName): true}
	for _, r := range run.Results {
		if uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; !want[uri] {
			t.Errorf("uri = %q, want the exact name encoded: %v", uri, want)
		}
	}
	if !strings.Contains(sarifURI("", evilName), "%0A%0A%23") {
		t.Errorf("uri does not encode the exact name: %q", sarifURI("", evilName))
	}
}

func TestJSONKeepsTheExactLocation(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, hostileReport()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct{ Location, Fingerprint string }
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range doc.Findings {
		seen[f.Location] = true
		if f.Fingerprint != finding.MakeFingerprint("SECRET-x", f.Location, "x") {
			t.Errorf("fingerprint of %q changed", f.Location)
		}
	}
	if !seen[evilName] || !seen[escName] {
		t.Errorf("locations = %v", seen)
	}
}

func TestMarkdownNamesUntrustedMode(t *testing.T) {
	const line = "- 받은 저장소 모드: --untrusted\n"
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Report{Target: "x", ScannedAt: time.Now(), Untrusted: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), line) {
		t.Errorf("%s", buf.String())
	}
	buf.Reset()
	if err := WriteMarkdown(&buf, Report{Target: "x", ScannedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "받은 저장소 모드") {
		t.Errorf("%s", buf.String())
	}
}
