package autorun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func viaRunAll(t *testing.T, root string) []finding.Finding {
	t.Helper()
	got, st := checker.RunAll(context.Background(), []checker.Checker{New(testData)}, checker.Target{Root: root}, 0)
	if st[0].Status != checker.StatusOK {
		t.Fatalf("status %+v", st[0])
	}
	return got
}

// I2: 보통 명령은 JSON 키(command, label, type)와 합쳐 세지 않으므로 그대로 보인다.
func TestOrdinaryCommandsAreShown(t *testing.T) {
	for _, cmd := range []string{
		"npm install && npm run build && npm run dev",
		"curl -fsSL https://cdn.example.test/install.sh | bash",
	} {
		root := t.TempDir()
		write(t, root, ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"dev","type":"shell","command":"`+cmd+`",`+folderOpen+`}]}`)
		write(t, root, "package.json", `{"scripts":{"postinstall":"`+cmd+`"}}`)
		fs := viaRunAll(t, root)
		if len(fs) < 2 {
			t.Fatalf("%q: findings = %d", cmd, len(fs))
		}
		for _, f := range fs {
			if !strings.Contains(f.Evidence, cmd) || strings.Contains(f.Evidence, "가림") {
				t.Errorf("%s evidence %q lacks %q", f.ID, f.Evidence, cmd)
			}
		}
	}
}

// 인자 배열로 나눠 적은 구문과 키는 이어 붙인 모양에서 찾아 가린다(키 이름은 합치지 않는다).
func TestSplitArgsAreStillHidden(t *testing.T) {
	var w []string
	for i := 0; i < 12; i++ {
		sum := sha256.Sum256([]byte("b3-ar" + string(rune('a'+i))))
		b := make([]byte, 6)
		for j := range b {
			b[j] = 'a' + sum[j]%26
		}
		w = append(w, string(b))
	}
	sum := sha256.Sum256([]byte("b3-ar-key"))
	key := hex.EncodeToString(sum[:])
	halves := make([]string, len(w))
	for i, s := range w {
		halves[i] = s + "/"
	}
	cases := map[string][]string{
		"words":        append([]string{"-c"}, w...),
		"slash pieces": halves,
		"key halves":   {"--key", key[:32], key[32:]},
		"key quarters": {key[:16], key[16:32], key[32:48], key[48:]},
	}
	for name, args := range cases {
		root := t.TempDir()
		a, _ := json.Marshal(args)
		write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"run","type":"process","command":"node","args":`+string(a)+`,`+folderOpen+`}]}`)
		fs := viaRunAll(t, root)
		if len(fs) != 1 {
			t.Fatalf("%s: findings = %d", name, len(fs))
		}
		ev := strings.ToLower(fs[0].Evidence)
		for _, word := range w {
			if strings.Contains(ev, word) {
				t.Errorf("%s: word shown: %q", name, ev)
				break
			}
		}
		for i := 0; i+8 <= len(key); i += 8 {
			if strings.Contains(ev, key[i:i+8]) {
				t.Errorf("%s: key piece shown: %q", name, ev)
				break
			}
		}
		if !strings.Contains(ev, `"command":"node"`) || !strings.Contains(ev, "가림") {
			t.Errorf("%s: evidence %q", name, ev)
		}
	}
}
