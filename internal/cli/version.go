package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"runtime/debug"
	"sort"
	"strings"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
)

// Version is set at link time (-X .../internal/cli.Version=1.0.0) by release
// builds. When it is empty, VersionInfo falls back to the build information.
var Version = ""

// dataBundles names the embedded data directories whose hashes `adk version`
// prints, in output order.
var dataBundles = []struct{ label, dir string }{
	{"규칙 데이터", "rules"},
	{"설명 데이터", "explain"},
	{"고치는 방법 데이터", "fixes"},
	{"매핑 데이터", "mappings"},
}

// VersionInfo returns the tool version, the source commit and a hash of each
// embedded data bundle (keyed by directory name). The version is the linked
// value, else the module version from the build information, else "dev". The
// commit is the first 12 characters of vcs.revision, with "-dirty" appended
// when the tree was modified; it is empty when the build carries no VCS
// information.
func VersionInfo() (version, commit string, dataHashes map[string]string) {
	version = Version
	var revision string
	var modified bool
	if bi, ok := debug.ReadBuildInfo(); ok {
		if version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = strings.TrimPrefix(bi.Main.Version, "v")
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	if version == "" {
		version = "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision != "" && modified {
		revision += "-dirty"
	}
	dataHashes = make(map[string]string, len(dataBundles))
	for _, b := range dataBundles {
		dataHashes[b.dir] = hashDir(aidefensekit.Data, b.dir)
	}
	return version, revision, dataHashes
}

// toolVersion is the value reports and the HTTP user agent carry.
func toolVersion() string {
	v, _, _ := VersionInfo()
	return v
}

// hashDir hashes every file under dir in sorted path order as path, NUL,
// content, NUL. Line endings are normalised to LF first so that a checkout
// with CRLF gives the same value. It returns the first 16 hex characters of
// the SHA-256, or "읽지 못함" when the bundle cannot be read.
func hashDir(fsys fs.FS, dir string) string {
	var paths []string
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return "읽지 못함"
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return "읽지 못함"
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write([]byte(strings.ReplaceAll(string(b), "\r\n", "\n")))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func runVersion(stdout io.Writer) int {
	v, commit, hashes := VersionInfo()
	fmt.Fprintf(stdout, "adk %s\n", v)
	if commit == "" {
		commit = "알 수 없음"
	}
	fmt.Fprintf(stdout, "커밋: %s\n", commit)
	for _, b := range dataBundles {
		fmt.Fprintf(stdout, "%s: %s\n", b.label, hashes[b.dir])
	}
	return 0
}
