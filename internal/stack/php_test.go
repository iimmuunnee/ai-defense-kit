package stack

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectPHP(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []string
	}{
		{"composer", "composer.json", []string{"php"}},
		{"php file", "index.php", []string{"php"}},
		{"nested php file", "public/board/index.php", []string{"php"}},
		{"phtml", "views/a.phtml", []string{"php"}},
		{"vendor only", "vendor/x/a.php", []string{}},
		{"no php", "index.html", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, filepath.FromSlash(tt.file))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
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
