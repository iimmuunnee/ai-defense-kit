package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func evidenceCodeReport() Report {
	r := fixedReport()
	r.ScannedAt = time.Date(2026, 11, 5, 16, 30, 0, 0, time.FixedZone("KST", 9*3600))
	r.Target = "/home/dev/work/my-app"
	r.TargetName = "my-app"
	r.GitDirty = DirtyYes
	r.Components = []Component{{Name: "osv-scanner", Version: "v2.7.0"}, {Name: "gitleaks", Version: "v8.30.1"}}
	r.Data = DataVersions{
		Rules: &DataSet{Origin: OriginBuiltin, SHA256: "aaaa", Count: 12},
		Mappings: MappingData{
			DataSet: DataSet{Origin: OriginBuiltin, SHA256: "bbbb", Count: 14},
			Items:   []MappingSource{{ID: "ISMSP-2.10.4", SourceVersion: "2023-11", ReviewStatus: "draft"}},
		},
	}
	t1 := time.Date(2026, 11, 5, 16, 29, 50, 0, time.FixedZone("KST", 9*3600))
	r.Checks[2].External = []checker.ExternalData{
		{Name: "OSV", Mode: checker.ModeOnline, Status: checker.ExternalFailed, Note: "조회 실패"},
		{Name: "CISA KEV", Mode: checker.ModeOnline, Status: checker.ExternalUsed, FetchedAt: &t1},
	}
	r.IgnoredFindings = []finding.Finding{
		{ID: "SECRET-x", Severity: finding.Medium, Location: "tests/fixture.py", Fingerprint: "9999aaaa9999aaaa", Evidence: "SECRETMARK"},
	}
	r.Ignored = 1
	return r
}

func evidenceAssetsReport() Report {
	r := fixedAssetsReport()
	r.KnownList = "/home/dev/lists/known.txt"
	r.Data.Mappings = MappingData{DataSet: DataSet{Origin: OriginBuiltin, SHA256: "bbbb", Count: 14}}
	r.Checks[0].External = []checker.ExternalData{{Name: "crt.sh", Mode: checker.ModeOnline, Status: checker.ExternalUsed,
		FetchedAt: func() *time.Time { t := time.Date(2026, 11, 4, 9, 29, 0, 0, time.UTC); return &t }()}}
	return r
}

func evidenceString(t *testing.T, r Report, files []ReportFile) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteEvidence(&buf, r, files); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func checkEvidenceGolden(t *testing.T, r Report, files []ReportFile, path string) {
	t.Helper()
	got := evidenceString(t, r, files)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("evidence differs from golden (run with -update):\n%s", got)
	}
}

var evidenceFiles = []ReportFile{{File: "adk-report.md", SHA256: "abc123"}, {File: "adk-report.json", SHA256: "def456"}}

func TestEvidenceGolden(t *testing.T) {
	checkEvidenceGolden(t, evidenceCodeReport(), evidenceFiles, "../../testdata/report/golden-evidence.json")
}

func TestEvidenceAssetsGolden(t *testing.T) {
	checkEvidenceGolden(t, evidenceAssetsReport(), evidenceFiles[:1], "../../testdata/report/golden-evidence-assets.json")
}

func decodeEvidence(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEvidenceEmptyListsNotNull(t *testing.T) {
	out := evidenceString(t, Report{Target: "x", ScannedAt: time.Now()}, nil)
	m := decodeEvidence(t, out)
	for _, k := range []string{"findings", "ignored", "reports", "checks", "external_data"} {
		if a, ok := m[k].([]any); !ok || len(a) != 0 {
			t.Errorf("%s should be [], got %v", k, m[k])
		}
	}
	if c, ok := m["tool"].(map[string]any)["components"].([]any); !ok || len(c) != 0 {
		t.Errorf("components should be []")
	}
	if git := m["git"].(map[string]any); git["dirty"] != DirtyUnknown || git["commit"] != "" {
		t.Errorf("git = %v", git)
	}
}

func TestEvidenceHasNoSecretText(t *testing.T) {
	r := evidenceCodeReport()
	r.Findings[0].Evidence = "EVIDENCEMARK"
	for _, s := range []string{"EVIDENCEMARK", "SECRETMARK", "키가 저장소에 있으면", "환경 변수로 옮기세요", "4.17.21 이상", "api_key", "K7Q2"} {
		if strings.Contains(evidenceString(t, r, nil), s) {
			t.Errorf("evidence leaks %q", s)
		}
	}
}

func TestEvidenceListsIgnoredFindings(t *testing.T) {
	out := evidenceString(t, evidenceCodeReport(), nil)
	for _, want := range []string{`"9999aaaa9999aaaa"`, `"SECRET-x"`, `"medium"`, `"tests/fixture.py"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestEvidenceShowsFailedChecks(t *testing.T) {
	out := evidenceString(t, evidenceCodeReport(), nil)
	for _, want := range []string{`"failed"`, "OSV 조회 실패: network unreachable", "git 기록이 없어 과거 커밋은 확인하지 못함"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	r := Report{Target: "x", Checks: []checker.CheckStatus{{Name: "deps", Status: checker.StatusSkipped}}}
	if !strings.Contains(evidenceString(t, r, nil), `"skipped"`) {
		t.Error("skipped missing")
	}
}

func TestEvidenceScrubsPaths(t *testing.T) {
	r := evidenceCodeReport()
	r.ScanRoot = "/home/dev/work/my-app"
	r.PrivatePaths = []string{"/home/dev/.cache/osv"}
	r.Checks[2].Error = "열 수 없음: /home/dev/work/my-app/package-lock.json, /home/dev/.cache/osv/db"
	r.Checks[1].Warnings = []string{"경고 /home/dev/work/my-app/x"}
	r.Checks[2].External[0].Note = "DB /home/dev/.cache/osv 없음"
	r.KnownList = `C:\Users\dev\secret dir\known.txt`
	out := evidenceString(t, r, nil)
	for _, bad := range []string{"/home/dev", "secret dir", `C:\Users`} {
		if strings.Contains(out, bad) {
			t.Errorf("path %q leaked:\n%s", bad, out)
		}
	}
	for _, want := range []string{"./package-lock.json", "<경로>/db", `"known_list": "known.txt"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestEvidenceNoticeAndSignature(t *testing.T) {
	m := decodeEvidence(t, evidenceString(t, evidenceCodeReport(), nil))
	if m["notice"] != EvidenceNotice {
		t.Errorf("notice = %v", m["notice"])
	}
	if v, ok := m["signature"]; !ok || v != nil {
		t.Errorf("signature = %v, want null", v)
	}
	if m["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v", m["schema_version"])
	}
	if !strings.Contains(evidenceString(t, evidenceCodeReport(), nil), `"signature": null`) {
		t.Error("signature must be JSON null")
	}
}

func TestEvidenceUsesTargetName(t *testing.T) {
	out := evidenceString(t, evidenceCodeReport(), nil)
	if !strings.Contains(out, `"target": "my-app"`) || strings.Contains(out, "/home/dev") {
		t.Errorf("target not name only:\n%s", out)
	}
}
