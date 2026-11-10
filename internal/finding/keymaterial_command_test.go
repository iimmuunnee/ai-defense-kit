package finding

import (
	"strings"
	"testing"
)

// 명령 규칙: 전체는 글 규칙, 공백으로 나눈 낱말마다 값 규칙.
func TestCommandRule(t *testing.T) {
	w := genWords("b1-command", 12)
	up := make([]string, len(w))
	for i, s := range w {
		up[i] = strings.ToUpper(s)
	}
	mixed := w[0]
	for i, s := range w[1:] {
		mixed += []string{"-", "_", "."}[i%3] + s
	}
	for name, v := range map[string]string{
		"upper snake word": "echo " + strings.Join(up, "_") + " && npm run dev",
		"mixed word":       "node -e " + mixed,
		"spaced":           "echo " + strings.Join(w, " "),
	} {
		got := strings.ToLower(ScrubCommand(v))
		for _, word := range w {
			if strings.Contains(got, word) {
				t.Errorf("%s: %q -> word shown", name, got)
				break
			}
		}
	}
	for _, v := range []string{
		"curl -fsSL https://get.pnpm.io/install.sh | sh - && pnpm install && pnpm run dev",
		"npx --yes prisma migrate deploy && npx prisma generate && npm run build && npm run start",
		"cd frontend && npm ci && npm run build && cd .. && go run ./cmd/server",
	} {
		if got := ScrubCommand(v); got != v {
			t.Errorf("%q -> %q", v, got)
		}
		if ScrubValue(v) == v {
			t.Errorf("value rule no longer hides %q: the command rule test lost its point", v)
		}
	}
}
