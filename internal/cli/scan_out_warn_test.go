package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

const outInsideRootWarning = "출력 폴더가 점검하는 저장소 안에 있습니다. 저장소가 심어 둔 링크는 따라가지 않지만, 저장소 밖 폴더를 쓰는 편이 낫습니다."

func TestUntrustedOutInsideRootWarns(t *testing.T) {
	useFakeDeps(t)
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, sampleApp, app)
	_, _, stderr := runCLI(t, "scan", app, "--untrusted", "--out", filepath.Join(app, "out"))
	if !strings.Contains(stderr, outInsideRootWarning) {
		t.Fatalf("no warning: %s", stderr)
	}
	_, _, stderr = runCLI(t, "scan", app, "--untrusted", "--out", t.TempDir())
	if strings.Contains(stderr, "출력 폴더가 점검하는 저장소 안에") {
		t.Fatalf("warned for an outside folder: %s", stderr)
	}
	_, _, stderr = runCLI(t, "scan", app, "--out", filepath.Join(app, "out2"))
	if strings.Contains(stderr, "출력 폴더가 점검하는 저장소 안에") {
		t.Fatalf("warned without --untrusted: %s", stderr)
	}
}
