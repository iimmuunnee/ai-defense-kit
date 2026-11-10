package stack

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectFixtures(t *testing.T) {
	tests := []struct {
		dir  string
		want []string
	}{
		{"nextjs", []string{"nextjs"}},
		{"fastapi", []string{"fastapi"}},
		{"supabase", []string{"supabase"}},
		{"mixed", []string{"fastapi", "nextjs", "supabase"}},
		{"empty", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			got, err := Detect(filepath.Join("..", "..", "testdata", "stacks", tt.dir))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectMissingRoot(t *testing.T) {
	if _, err := Detect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestDetectRootIsFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "f", "x")
	if _, err := Detect(filepath.Join(root, "f")); err == nil {
		t.Fatal("expected error when root is a file")
	}
}

func TestDetectCases(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"excluded node_modules", map[string]string{"node_modules/next/package.json": `{"dependencies":{"next":"1"}}`}, []string{}},
		{"excluded other dirs", map[string]string{
			".git/package.json": `{"dependencies":{"next":"1"}}`, ".next/package.json": `{"dependencies":{"next":"1"}}`,
			"dist/package.json": `{"dependencies":{"next":"1"}}`, "build/requirements.txt": "fastapi\n",
			"vendor/requirements.txt": "fastapi\n", ".venv/requirements.txt": "fastapi\n", "__pycache__/requirements.txt": "fastapi\n"}, []string{}},
		{"depth 3 ok", map[string]string{"a/b/c/package.json": `{"dependencies":{"next":"1"}}`}, []string{"nextjs"}},
		{"depth 4 too deep", map[string]string{"a/b/c/d/package.json": `{"dependencies":{"next":"1"}}`}, []string{}},
		{"supabase js in package.json", map[string]string{"package.json": `{"dependencies":{"@supabase/supabase-js":"2"}}`}, []string{"supabase"}},
		{"supabase folder only nested is ignored", map[string]string{"sub/supabase/config.toml": "x"}, []string{}},
		{"malformed package.json skipped", map[string]string{"package.json": `{oops`, "x/package.json": `{"dependencies":{"next":"1"}}`}, []string{"nextjs"}},
		{"nested python manifest", map[string]string{"services/api/requirements.txt": "fastapi==0.1\n"}, []string{"fastapi"}},
		{"fastapi-utils is not fastapi", map[string]string{"requirements.txt": "fastapi-utils==1\n# fastapi\n"}, []string{}},
		{"fastapi case and specifiers", map[string]string{"requirements.txt": "FastAPI~=0.1\n"}, []string{"fastapi"}},
		{"fastapi at eof no newline", map[string]string{"requirements.txt": "uvicorn\nfastapi"}, []string{"fastapi"}},
		{"poetry.lock name", map[string]string{"poetry.lock": "[[package]]\nname = \"fastapi\"\nversion = \"0.1\"\n"}, []string{"fastapi"}},
		{"uv.lock name", map[string]string{"uv.lock": "[[package]]\nname = \"fastapi\"\n"}, []string{"fastapi"}},
		{"single-line array", map[string]string{"pyproject.toml": "[project]\ndependencies = [\"fastapi>=0.110\", \"uvicorn\"]\n"}, []string{"fastapi"}},
		{"fastapi second in array", map[string]string{"pyproject.toml": "dependencies = [\"uvicorn\", \"fastapi\"]\n"}, []string{"fastapi"}},
		{"fastapi-utils in array", map[string]string{"pyproject.toml": "dependencies = [\"fastapi-utils>=1\"]\n"}, []string{}},
		{"poetry pyproject", map[string]string{"pyproject.toml": "[tool.poetry.dependencies]\nfastapi = \"^0.1\"\n"}, []string{"fastapi"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, c := range tt.files {
				write(t, root, rel, c)
			}
			got, err := Detect(root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectSymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	write(t, real, "package.json", `{"dependencies":{"next":"1"}}`)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	got, err := Detect(link)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nextjs"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

const nextPackage = `{"dependencies":{"next":"15.0.0"}}`

// A manifest that is a link is not read: it could point at /dev/zero.
func TestDetectDoesNotFollowLinkedManifests(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "package.json", nextPackage)
	write(t, outside, "requirements.txt", "fastapi==0.100.0\n")
	for _, name := range []string{"package.json", "requirements.txt"} {
		if err := os.Symlink(filepath.Join(outside, name), filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("Detect = %v", got)
	}
}

func TestDetectSurvivesLinkToEndlessFile(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	root := t.TempDir()
	for _, name := range []string{"package.json", "requirements.txt"} {
		if err := os.Symlink("/dev/zero", filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	got, err := Detect(root)
	if err != nil || len(got) != 0 {
		t.Errorf("Detect = %v, %v", got, err)
	}
}

// Only the first 1MiB of a manifest is read.
func TestDetectReadsOversizedManifestsOnlyInPart(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"dependencies":{"next":"15.0.0"},"pad":"`+strings.Repeat("x", 1<<20)+`"}`)
	write(t, root, "requirements.txt", strings.Repeat("# pad\n", 1<<18)+"fastapi==0.100.0\n")
	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("Detect = %v", got)
	}
}
