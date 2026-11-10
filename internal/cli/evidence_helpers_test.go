package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// validateSARIF checks data against the SARIF 2.1.0 schema in testdata,
// without touching the network.
func validateSARIF(t *testing.T, data []byte) {
	t.Helper()
	f, err := os.Open(sarifSchemaPath)
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

type evDataSet struct {
	Origin string `json:"origin"`
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}

type evDoc struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Target        string `json:"target"`
	KnownList     string `json:"known_list"`
	Git           struct {
		Commit string `json:"commit"`
		Dirty  string `json:"dirty"`
	} `json:"git"`
	Data struct {
		Rules    *evDataSet `json:"rules"`
		Mappings struct {
			evDataSet
			Items []struct {
				ID            string `json:"id"`
				SourceVersion string `json:"source_version"`
				ReviewStatus  string `json:"review_status"`
			} `json:"items"`
		} `json:"mappings"`
	} `json:"data"`
	Checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"checks"`
	Findings []struct {
		Fingerprint string `json:"fingerprint"`
		ID          string `json:"id"`
		Location    string `json:"location"`
	} `json:"findings"`
	Ignored []struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"ignored"`
	Reports []struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	} `json:"reports"`
	Signature any `json:"signature"`
}

func readEvidence(t *testing.T, dir string) (evDoc, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "adk-evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ev evDoc
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatal(err)
	}
	return ev, b
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestScanWritesEvidenceWithOut(t *testing.T) {
	useFakeDeps(t)
	out := t.TempDir()
	code, _, se := runCLI(t, "scan", "--fail-on", "none", sampleApp, "--format", "md,sarif,json", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	for _, n := range []string{"adk-report.md", "adk-report.sarif", "adk-report.json", "adk-evidence.json"} {
		if _, err := os.Stat(filepath.Join(out, n)); err != nil {
			t.Errorf("%s missing: %v", n, err)
		}
	}
	ev, _ := readEvidence(t, out)
	if ev.SchemaVersion != 1 || ev.Signature != nil || ev.Kind != "code" || ev.Target != "sample-app" {
		t.Errorf("header: %+v", ev)
	}
	if len(ev.Reports) != 3 {
		t.Fatalf("reports: %+v", ev.Reports)
	}
	for _, r := range ev.Reports {
		if r.File == "adk-evidence.json" || strings.ContainsAny(r.File, `/\`) {
			t.Errorf("bad report entry %q", r.File)
		}
		if want := fileSHA(t, filepath.Join(out, r.File)); r.SHA256 != want {
			t.Errorf("%s: sha %s, file %s", r.File, r.SHA256, want)
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "adk-report.sarif"))
	validateSARIF(t, b)
	if !strings.Contains(se, "증적 파일을 저장했습니다: "+filepath.Join(out, "adk-evidence.json")) {
		t.Errorf("stderr: %s", se)
	}
}

// sarifSchemaPath is absolute so that tests which change the working folder
// can still validate.
var sarifSchemaPath, _ = filepath.Abs("../../testdata/sarif/sarif-schema-2.1.0.json")

// scrubTempPaths takes the test's own temp folders out of an output before it
// is searched for pieces of a fake value. Their names end in random digits,
// which can match any short piece of a hex key; the program prints these
// paths on purpose, so they are not leaks. Every form the outputs use is
// removed: as the OS writes it, with '/' (SARIF, Markdown) and with JSON's
// doubled backslashes, each also with its folder links resolved.
func scrubTempPaths(text string, dirs ...string) string {
	var forms []string
	for _, d := range dirs {
		ds := []string{d}
		if r, err := filepath.EvalSymlinks(d); err == nil && r != d {
			ds = append(ds, r)
		}
		for _, d := range ds {
			forms = append(forms, strings.ReplaceAll(d, `\`, `\\`), d, filepath.ToSlash(d))
		}
	}
	for _, f := range forms {
		if f != "" {
			text = strings.ReplaceAll(text, f, "<temp>")
		}
	}
	return text
}

// scrubTempPaths takes out the temp paths only: the same digits elsewhere in
// the text are still there to be found.
func TestScrubTempPathsOnlyPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "TestX1645")
	text := "saved: " + filepath.Join(root, "002", "adk-report.md") + "\n" +
		`"target": "` + strings.ReplaceAll(filepath.Join(root, "001"), `\`, `\\`) + `"` + "\n" +
		"uri: " + filepath.ToSlash(filepath.Join(root, "001", "a.ts")) + "\n" +
		"evidence: 0x1645"
	got := scrubTempPaths(text, root)
	if strings.Count(got, "1645") != 1 || !strings.Contains(got, "evidence: 0x1645") {
		t.Errorf("got %q", got)
	}
}
