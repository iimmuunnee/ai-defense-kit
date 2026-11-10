package stack

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectReact(t *testing.T) {
	tests := []struct {
		name, pkg string
		want      []string
	}{
		{"dependency", `{"dependencies":{"react":"19.0.0"}}`, []string{"react"}},
		{"dev dependency", `{"devDependencies":{"react":"19.0.0"}}`, []string{"react"}},
		{"next project", `{"dependencies":{"next":"15.0.0","react":"19.0.0"}}`, []string{"nextjs"}},
		{"next as dev dependency", `{"dependencies":{"react":"19.0.0"},"devDependencies":{"next":"15.0.0"}}`, []string{"nextjs"}},
		{"similar name", `{"dependencies":{"react-native-web-lite":"1.0.0"}}`, []string{}},
		{"no react", `{"dependencies":{"express":"5.0.0"}}`, []string{}},
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
