package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WL-001이 읽은 줄의 개인 키 값은 어느 출력 형식에도 나오지 않아야 한다.
// 값은 시험 안에서 조립하며 파일로 저장해 두지 않는다.
func TestWalletKeyValuesStayOutOfEveryOutput(t *testing.T) {
	useFakeDeps(t)
	key := "0x" + strings.Repeat("4c7d", 16)
	phrase := strings.Join(append([]string{"zxalpha", "zxbravo", "zxcobalt", "zxdelta", "zxember", "zxfalcon"},
		"zxgarnet", "zxharbor", "zxisland", "zxjungle", "zxkernel", "zxlumen"), " ")
	app := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies":{"ethers":"6.0.0"}}`,
		".env":         "PRIVATE_KEY=" + key + "\nMNEMONIC=" + phrase + "\n",
		"src/a.ts":     `const w = new Wallet("` + key + `", provider);` + "\n",
	}
	for name, body := range files {
		p := filepath.Join(app, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	code, so, se := runCLI(t, "scan", app, "--format", "md,json,sarif", "--out", out, "--offline")
	if code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	all := so + se
	ents, err := os.ReadDir(out)
	if err != nil || len(ents) < 4 {
		t.Fatalf("outputs: %v %v", ents, err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		all += string(b)
		if e.Name() == "adk-report.json" && strings.Count(string(b), `"id": "WL-001"`) < 3 {
			t.Errorf("WL-001 should be reported for all three lines:\n%s", b)
		}
	}
	for _, s := range []string{key, strings.TrimPrefix(key, "0x"), "4c7d4c7d", phrase, "zxalpha", "zxlumen"} {
		if strings.Contains(all, s) {
			t.Errorf("%q appears in the outputs", s)
		}
	}
}
