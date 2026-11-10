package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig(t *testing.T) {
	p := writeFile(t, "w.yaml", `targets:
  - key: evm:main
    kind: evm-wallet
    options:
      address: "0xabc"
  - key: evm:second
    kind: evm-wallet
`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 2 || cfg.Targets[0].Key != "evm:main" || cfg.Targets[0].Options["address"] != "0xabc" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	cases := map[string]string{
		"dup key":       "targets:\n  - {key: a, kind: evm-wallet}\n  - {key: a, kind: evm-wallet}\n",
		"unknown kind":  "targets:\n  - {key: a, kind: nope}\n",
		"empty key":     "targets:\n  - {key: \"\", kind: evm-wallet}\n",
		"unknown field": "targets:\n  - {key: a, kind: evm-wallet, extra: 1}\n",
		"unknown top":   "targets: []\nfoo: 1\n",
		"corrupt":       "targets: [",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeFile(t, "w.yaml", body)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
	_, err := LoadConfig(writeFile(t, "w.yaml", "targets:\n  - {key: a, kind: nope}\n"))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("error should name the kind: %v", err)
	}
}
