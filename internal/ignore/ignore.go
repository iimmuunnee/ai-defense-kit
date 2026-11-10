// Package ignore reads the .adkignore file: one finding fingerprint per line.
package ignore

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileName is the name of the ignore file inside the scanned folder.
const FileName = ".adkignore"

// Set is a set of fingerprints to ignore.
type Set map[string]struct{}

// Has reports whether fingerprint is ignored.
func (s Set) Has(fingerprint string) bool {
	_, ok := s[fingerprint]
	return ok
}

// Load reads <root>/.adkignore. A missing file gives an empty Set.
// Text after '#' is a comment; blank lines are skipped.
func Load(root string) (Set, error) {
	f, err := os.Open(filepath.Join(root, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return Set{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := Set{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			line = strings.TrimPrefix(line, "\uFEFF") // UTF-8 BOM (Windows Notepad)
			first = false
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			s[line] = struct{}{}
		}
	}
	return s, sc.Err()
}
