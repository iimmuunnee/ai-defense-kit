package deps

import (
	"os"
	"testing"
)

func TestParseRequirements(t *testing.T) {
	cases := []struct {
		line  string
		name  string // "" = excluded
		exact bool
	}{
		{"Django==4.2.1", "django", true},
		{`requests[security]==2.31.0 ; python_version>"3"`, "requests", true},
		{"numpy>=1.2", "numpy", false},
		{"foo == 2.8.*", "foo", false},
		{"Bar_Baz===1.0", "bar-baz", true},
		{"pkg==1.0 --hash=sha256:abc", "pkg", true},
		{"a.b__c==1", "a-b-c", true},
		{"x==1.0, <2", "x", false},
		{"y~=1.4.2", "y", false},
		{"z!=1.0", "z", false},
		{"w==1.0 # comment", "w", true},
		{"pytest", "pytest", false},
		{"# Django==1", "", false},
		{"", "", false},
		{"-r dev.txt", "", false},
		{"-c constraints.txt", "", false},
		{"-e .", "", false},
		{"https://x/y.whl", "", false},
		{"./downloads/numpy-1.9.2-cp34-none-win32.whl", "", false},
		{"name @ https://x", "", false},
		{"name@https://x", "", false},
	}
	for _, c := range cases {
		got := ParseRequirements(c.line)
		if c.name == "" {
			if len(got) != 0 {
				t.Errorf("%q: want excluded, got %+v", c.line, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Name != c.name || got[0].Exact != c.exact {
			t.Errorf("%q: got %+v, want name=%s exact=%v", c.line, got, c.name, c.exact)
		}
	}
}

func TestParseRequirementsLinesAndContinuation(t *testing.T) {
	got := ParseRequirements("# c\r\nfoo==1 \\\r\n    --hash=sha256:a \\\r\n    --hash=sha256:b\r\nbar>=2\r\n")
	if len(got) != 2 || !got[0].Exact || got[0].Line != 2 || got[1].Name != "bar" || got[1].Line != 5 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseRequirementsFixture(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/deps/requirements/requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	var exact, other []string
	for _, r := range ParseRequirements(string(b)) {
		if r.Exact {
			exact = append(exact, r.Name)
		} else {
			other = append(other, r.Name)
		}
	}
	if len(exact) != 4 || len(other) != 3 {
		t.Errorf("exact=%v other=%v", exact, other)
	}
}

func TestParseRequirementsGaps(t *testing.T) {
	// BOM
	if got := ParseRequirements("\ufeffDjango==4.2.1\n"); len(got) != 1 || got[0].Name != "django" || !got[0].Exact {
		t.Errorf("BOM: %+v", got)
	}
	// a comment ending in a backslash does not swallow the next line
	got := ParseRequirements("# note \\\nflask==1.0\n")
	if len(got) != 1 || got[0].Name != "flask" || got[0].Line != 2 {
		t.Errorf("comment continuation: %+v", got)
	}
	// tab before comment and option
	got = ParseRequirements("a==1\t# c\nb==2\t--hash=sha256:x\n")
	if len(got) != 2 || !got[0].Exact || !got[1].Exact {
		t.Errorf("tabs: %+v", got)
	}
}

func TestIncludePath(t *testing.T) {
	for in, want := range map[string]string{
		"-r base.txt": "base.txt", "--requirement=base.txt": "base.txt",
		"-r\tbase.txt # c": "base.txt", "-rbase.txt": "base.txt",
		"-c c.txt": "", "-e .": "", "# -r x.txt": "",
	} {
		got, ok := includePath(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v", in, got, ok)
		}
	}
}

func TestIsRequirementsFileMatchesScalibr(t *testing.T) {
	// osv-scalibr: extension .txt and "requirements" anywhere in the name
	for name, want := range map[string]bool{
		"requirements.txt": true, "requirements-dev.txt": true,
		"dev-requirements.txt": true, "test_requirements.txt": true,
		"requirements.in": false, "requirements.txt.bak": false,
		"Requirements.txt": false, "base.txt": false,
	} {
		if got := isRequirementsFile(name); got != want {
			t.Errorf("%q: got %v want %v", name, got, want)
		}
	}
}

func TestParseRequirementsVersion(t *testing.T) {
	for line, want := range map[string]string{
		"numpy==1.24.4":                       "1.24.4",
		`numpy==1.24.4; python_version<"3.9"`: "1.24.4",
		"Bar===1.0+local":                     "1.0+local",
		"x == 2.0 --hash=sha256:a":            "2.0",
		"numpy>=1.20":                         "",
		"foo==2.*":                            "",
		"pytest":                              "",
	} {
		got := ParseRequirements(line)
		if len(got) != 1 || got[0].Version != want || got[0].Exact != (want != "") {
			t.Errorf("%q: got %+v, want version %q", line, got, want)
		}
	}
}
