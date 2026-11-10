package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// sarifURIs renders one finding per location under root and returns the
// artifact URIs in input order (an empty string when a result has none).
func sarifURIs(t *testing.T, root string, private []string, locs []string) []string {
	t.Helper()
	var fs []finding.Finding
	for i, l := range locs {
		fs = append(fs, finding.Finding{
			ID: "X-1", Source: "rules", Severity: finding.High, Confidence: finding.Certain,
			Title: "t", Location: l, Line: i + 1, Fingerprint: strings.Repeat("a", 16),
		})
	}
	var buf bytes.Buffer
	r := Report{Target: "x", ToolVersion: "v0.1.0", ScanRoot: root, PrivatePaths: private, Findings: fs}
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(locs))
	for _, res := range doc.Runs[0].Results {
		if len(res.Locations) == 0 {
			continue
		}
		pl := res.Locations[0].PhysicalLocation
		out[pl.Region.StartLine-1] = pl.ArtifactLocation.URI
	}
	return out
}

// Relative locations are never rewritten, whatever the root looks like.
func TestSARIFRelativeLocationsUnchanged(t *testing.T) {
	cases := []struct{ root, loc string }{
		{`C:\src\app`, "src/app/page.tsx"},
		{`C:\src\app`, "front/src/app/page.tsx"},
		{`C:\src\app`, "src/app.tsx"},
		{"/app", "src/app/page.tsx"},
		{"/app/src", "packages/app/src/index.js"},
		{"/home/me/proj", "home/me/proj/a.py"},
		{"/home/me/proj", "src/proj.py"},
	}
	for _, c := range cases {
		got := sarifURIs(t, c.root, nil, []string{c.loc})[0]
		if got != c.loc {
			t.Errorf("root %q loc %q: uri = %q", c.root, c.loc, got)
		}
	}
	// The leading "./" is still dropped.
	if got := sarifURIs(t, "/app", nil, []string{"./src/app/a.py"})[0]; got != "src/app/a.py" {
		t.Errorf("uri = %q", got)
	}
}

func TestSARIFAbsoluteLocations(t *testing.T) {
	cases := []struct{ root, loc, want string }{
		{"/home/me/proj", "/home/me/proj/src/a.py", "src/a.py"},
		{`C:\src\app`, `C:\src\app\src\app\page.tsx`, "src/app/page.tsx"},
		{`C:\src\app`, `C:/src/app/x/y.py`, "x/y.py"},
		{`C:\src\app`, `c:\SRC\app\x.py`, "x.py"},
		{"/app", "/app/src/app/page.tsx", "src/app/page.tsx"},
		// Outside the root: base name only.
		{"/home/me/proj", "/etc/secret/key.pem", "key.pem"},
		{"/home/me/proj", "/home/me/proj2/key.pem", "key.pem"},
		{`C:\src\app`, `D:\other\dir\key.pem`, "key.pem"},
		{`C:\src\app`, `D:/other/dir/key.pem`, "key.pem"},
		{"/home/me/proj", `\server\share\dir\key.pem`, "key.pem"},
		{"/home/me/proj", `C:\Users\me\key.pem`, "key.pem"},
	}
	for _, c := range cases {
		got := sarifURIs(t, c.root, nil, []string{c.loc})[0]
		if got != c.want {
			t.Errorf("root %q loc %q: uri = %q, want %q", c.root, c.loc, got, c.want)
		}
	}
	// A private path outside the root is also reduced to its base name.
	if got := sarifURIs(t, "/home/me/proj", []string{"/home/me/secret"}, []string{"/home/me/secret/x.py"})[0]; got != "x.py" {
		t.Errorf("uri = %q", got)
	}
}

func TestScrubAbsoluteFormBoundaries(t *testing.T) {
	for _, c := range []struct{ s, root, want string }{
		{"src/app/page.tsx", "/app", "src/app/page.tsx"},
		{"/application and /app2 and x/app", "/app", "/application and /app2 and x/app"},
		{"at /app/x, (/app) '/app/y' /app.", "/app", "at ./x, (.) './y' .."},
		// Free text still hides the stripped form after a separator.
		{"packages/app/src/index.js", "/app/src", "packages/./index.js"},
		{"/app/src/index.js", "/app/src", "./index.js"},
	} {
		if got := Scrub(c.s, c.root, nil); got != c.want {
			t.Errorf("Scrub(%q, %q) = %q, want %q", c.s, c.root, got, c.want)
		}
	}
}

func TestScrubBareVolumeRoot(t *testing.T) {
	for _, root := range []string{`D:\`, "C:/", "/", `D:`} {
		s := "see D:/x and /usr/lib and D:" + `\` + "y"
		if got := Scrub(s, root, []string{root}); got != s {
			t.Errorf("root %q changed text: %q", root, got)
		}
	}
}

func TestScrubBoundaryUsesOriginalString(t *testing.T) {
	if got := Scrub("opt/appopt/app", "/opt/app", nil); got != "opt/appopt/app" {
		t.Errorf("got %q", got)
	}
	if got := Scrub("xopt/app opt/app", "/opt/app", nil); got != "xopt/app ." {
		t.Errorf("got %q", got)
	}
}

func TestScrubDotBoundary(t *testing.T) {
	// A dot that starts a name part is not a boundary.
	if got := Scrub("opt/app.bak/secret", "/opt/app", nil); got != "opt/app.bak/secret" {
		t.Errorf("got %q", got)
	}
	// A sentence-ending dot after the path is.
	for _, c := range []struct{ s, want string }{
		{"failed in opt/app.", "failed in .."},
		{"failed in opt/app. Next", "failed in .. Next"},
		{"failed in opt/app.\nNext", "failed in ..\nNext"},
	} {
		if got := Scrub(c.s, "/opt/app", nil); got != c.want {
			t.Errorf("Scrub(%q) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestEvidenceIgnoredIndependentOfTieOrder(t *testing.T) {
	var fs []finding.Finding
	for i, id := range []string{"SECRET-a", "SECRET-b", "SECRET-c", "SECRET-d", "SECRET-a"} {
		fs = append(fs, finding.Finding{
			ID: id, Kind: "k", Source: "secrets", Severity: finding.Medium, Confidence: finding.Certain,
			Location: "tests/f.py", Line: 3, Fingerprint: strings.Repeat(string(rune('a'+i%4)), 16),
		})
	}
	render := func(in []finding.Finding) string {
		return evidenceString(t, Report{Target: "x", ToolVersion: "v0.1.0", IgnoredFindings: in}, nil)
	}
	want := render(fs)
	for seed := int64(1); seed <= 20; seed++ {
		if got := render(shuffled(fs, seed)); got != want {
			t.Fatalf("ignored order differs for seed %d", seed)
		}
	}
}
