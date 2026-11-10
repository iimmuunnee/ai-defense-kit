package stack

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// M6: ethers v5 하위 패키지, hardhat, @wagmi/core도 web3 프로젝트로 본다.
func TestDetectWeb3MorePackages(t *testing.T) {
	tests := []struct {
		name, pkg string
		want      []string
	}{
		{"ethersproject wallet", `{"dependencies":{"@ethersproject/wallet":"5.7.0"}}`, []string{"web3"}},
		{"ethersproject providers dev", `{"devDependencies":{"@ethersproject/providers":"5.7.0"}}`, []string{"web3"}},
		{"hardhat", `{"devDependencies":{"hardhat":"2.22.0"}}`, []string{"web3"}},
		{"wagmi core", `{"dependencies":{"@wagmi/core":"2.0.0"}}`, []string{"web3"}},
		{"similar names", `{"dependencies":{"@ethersproject":"1.0.0","@ethersprojectx/a":"1.0.0","hardhat-gas-reporter":"1.0.0","@wagmi/core-x":"1.0.0"}}`, []string{}},
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
