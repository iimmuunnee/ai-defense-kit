package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 값은 시험 안에서 조립하고 파일로 저장해 두지 않는다(임시 폴더의 시험용 저장소만 쓴다).
func TestKeyMaterialNeverReachesAnyOutput(t *testing.T) {
	useFakeDeps(t)
	sum := sha256.Sum256([]byte("cli-canary-one"))
	raw := hex.EncodeToString(sum[:])
	key := "0x" + raw
	words := append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
		"glide", "pencil", "north", "spring", "cabin", "onion")
	phrase := strings.Join(words, " ")

	app := t.TempDir()
	files := map[string]string{
		"package.json": `{"dependencies":{"react":"19.0.0","ethers":"6.0.0"}}`,
		".env": strings.Join([]string{
			"PRIVATE_KEY=" + key,
			"DEPLOYER_PRIVATE_KEY=" + raw,
			"VITE_PRIVATE_KEY=" + key,
			`MNEMONIC="` + phrase + `"`,
			"WALLET_MNEMONIC=" + phrase + " # don't share",
			"SEED_PHRASE=" + phrase + " (backup)",
		}, "\n") + "\n",
		"src/a.ts": "const m = `" + phrase + "\n",
		"src/b.ts": `await w.signTransaction(req.body, new Wallet("` + key + `"));` + "\n",
		"src/c.ts": `await c.signAuthorization({ account: privateKeyToAccount("` + key + `") });` + "\n",
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
	texts := map[string]string{"stdout": so, "stderr": se}
	ents, err := os.ReadDir(out)
	if err != nil || len(ents) < 4 {
		t.Fatalf("outputs: %v %v", ents, err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		texts[e.Name()] = string(b)
	}
	if !strings.Contains(texts["adk-report.json"], `"id": "WL-001"`) || !strings.Contains(texts["adk-report.json"], `"id": "RE-001"`) {
		t.Fatalf("expected WL-001 and RE-001 in the report:\n%s", texts["adk-report.json"])
	}
	longHex := regexp.MustCompile(`[0-9a-f]{16,}`)
	for name, text := range texts {
		if strings.Contains(text, raw) {
			t.Errorf("%s: full key", name)
		}
		for i := 0; i+16 <= len(raw); i++ {
			if strings.Contains(text, raw[i:i+16]) {
				t.Errorf("%s: 16-char piece of the key", name)
				break
			}
		}
		// 지문과 해시는 16자리 이상 16진수 덩어리이므로 4글자 조각 비교에서 뺀다.
		clean := longHex.ReplaceAllString(scrubTempPaths(text, filepath.Dir(app), filepath.Dir(out)), "")
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(clean, key[i:i+4]) {
				t.Errorf("%s: 4-char piece %q of the key", name, key[i:i+4])
			}
		}
		for _, w := range words {
			if strings.Contains(text, w) {
				t.Errorf("%s: word %q of the phrase", name, w)
			}
		}
	}
}
