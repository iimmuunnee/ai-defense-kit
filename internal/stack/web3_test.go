package stack

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectWeb3(t *testing.T) {
	tests := []struct {
		name, pkg string
		want      []string
	}{
		{"ethers", `{"dependencies":{"ethers":"6.0.0"}}`, []string{"web3"}},
		{"viem as dev dependency", `{"devDependencies":{"viem":"2.0.0"}}`, []string{"web3"}},
		{"web3", `{"dependencies":{"web3":"4.0.0"}}`, []string{"web3"}},
		{"safe sdk", `{"dependencies":{"@safe-global/protocol-kit":"4.0.0"}}`, []string{"web3"}},
		{"safe api kit", `{"devDependencies":{"@safe-global/api-kit":"2.0.0"}}`, []string{"web3"}},
		{"next with ethers", `{"dependencies":{"next":"15.0.0","react":"19.0.0","ethers":"6.0.0"}}`, []string{"nextjs", "web3"}},
		{"react with viem", `{"dependencies":{"react":"19.0.0","viem":"2.0.0"}}`, []string{"react", "web3"}},
		{"similar names", `{"dependencies":{"web3-utils":"4.0.0","ethers-lite":"1.0.0","@safe-globalx/a":"1.0.0","@safe-global":"1.0.0"}}`, []string{}},
		{"no web3", `{"dependencies":{"express":"5.0.0"}}`, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(tt.pkg), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := Detect(root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Detect = %v, want %v", got, tt.want)
			}
		})
	}
}

// A project without those packages keeps its stacks, whatever other files it has.
func TestDetectWeb3NeedsThePackage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hardhat.config.ts"), []byte("export default {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("web3==6.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("Detect = %v, want none", got)
	}
}
