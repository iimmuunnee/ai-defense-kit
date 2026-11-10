package report

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func TestScrubStrippedForms(t *testing.T) {
	root := `C:\Users\me\proj\w4`
	s := `(extracting as javascript/packagelockjson) Users/me/proj/w4/package-lock.json: could not extract; Users\me\proj\w4\x.json`
	got := Scrub(s, root, nil)
	if strings.Contains(got, "Users") || strings.Contains(got, "proj") {
		t.Fatalf("leak: %q", got)
	}
	if !strings.Contains(got, "./package-lock.json") {
		t.Fatalf("got %q", got)
	}
	// Other private paths become <경로>, with a leading separator too.
	got = Scrub("see /home/me/rules/a.yml and home/me/rules", "/work/app", []string{"/home/me/rules"})
	if strings.Contains(got, "home") || strings.Count(got, "<경로>") != 2 {
		t.Fatalf("got %q", got)
	}
}

func TestScrubStrippedFormBoundaries(t *testing.T) {
	// A single-segment root must not erase the word everywhere.
	got := Scrub("app apps /app/x myapp", "/app", nil)
	if got != "app apps ./x myapp" {
		t.Fatalf("got %q", got)
	}
	// Two segments, but glued to other name characters: left alone.
	got = Scrub("xopt/app opt/apple opt/app/y opt/app", "/opt/app", nil)
	if got != "xopt/app opt/apple ./y ." {
		t.Fatalf("got %q", got)
	}
	// Preceded by a separator (the stripped leading one) is replaced.
	got = Scrub(`\opt\app\z`, "/opt/app", nil)
	if got != `\.\z` && got != `.\z` {
		t.Fatalf("got %q", got)
	}
}

func shuffled(fs []finding.Finding, seed int64) []finding.Finding {
	out := append([]finding.Finding(nil), fs...)
	rand.New(rand.NewSource(seed)).Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Findings that tie on every sort key must still render the same bytes.
func TestOutputIndependentOfTieOrder(t *testing.T) {
	var fs []finding.Finding
	for i, id := range []string{"SECRET-a", "SECRET-b", "SECRET-c", "SECRET-d", "SECRET-e", "SECRET-a"} {
		fs = append(fs, finding.Finding{
			ID: id, Kind: "k", Source: "secrets", Title: "키 " + id, Severity: finding.High,
			Confidence: finding.Certain, Location: "config.py", Line: 3,
			Fingerprint: strings.Repeat(string(rune('a'+i%5)), 16),
		})
	}
	render := func(in []finding.Finding) (string, string) {
		r := Report{Target: "x", ToolVersion: "v0.1.0", Findings: in}
		var s, e bytes.Buffer
		if err := WriteSARIF(&s, r); err != nil {
			t.Fatal(err)
		}
		if err := WriteEvidence(&e, r, nil); err != nil {
			t.Fatal(err)
		}
		return s.String(), e.String()
	}
	ws, we := render(fs)
	for seed := int64(1); seed <= 20; seed++ {
		in := shuffled(fs, seed)
		gs, ge := render(in)
		if gs != ws {
			t.Fatalf("sarif differs for seed %d", seed)
		}
		if ge != we {
			t.Fatalf("evidence differs for seed %d", seed)
		}
	}
}
