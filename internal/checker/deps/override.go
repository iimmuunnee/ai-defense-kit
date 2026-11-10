package deps

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// overrideName stands in for the temporary file's path in messages, which reach
// reports and the evidence file.
const overrideName = "(임시 설정 파일)"

// newEmptyOverride creates an empty file outside the repository. Given as
// ConfigOverridePath, it replaces every osv-scanner.toml in the repository, in
// any folder, so the repository cannot filter its own results.
func newEmptyOverride() (string, error) {
	f, err := os.CreateTemp("", "adk-osv-*.toml")
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// overrideFailure says why the file could not be made, without its path.
func overrideFailure(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("--untrusted에 필요한 임시 파일을 만들지 못해 의존성 점검을 하지 못했습니다: %w", err)
}

var errOverrideInRoot = errors.New("임시 폴더가 점검하는 폴더 안에 있습니다")

// isInside reports that path lies in root, which is already resolved.
func isInside(root, path string) bool {
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		path = filepath.Join(dir, filepath.Base(path))
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// hideOverride removes the file's path from a message of the scanner's.
func hideOverride(msg, path string) string {
	if path == "" {
		return msg
	}
	return strings.ReplaceAll(msg, path, overrideName)
}
