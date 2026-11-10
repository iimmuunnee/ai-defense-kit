package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A path the user has looked at can be left out, by the path the report shows.
func TestDeviceWalletsSkip(t *testing.T) {
	home := t.TempDir()
	devWrite(t, filepath.Join(home, "Documents", "repo", "README.md"), strings.Join(walletWords(t, 41, "english", 12), " "))
	devWrite(t, filepath.Join(home, ".config", "solana", "id.json"), "[]")
	if code, _, _ := runCLI(t, "device", "wallets", "--home", home); code != 1 {
		t.Fatalf("without --skip: code=%d", code)
	}
	code, out, errs := runCLI(t, "device", "wallets", "--home", home,
		"--skip", filepath.Join(home, "Documents", "repo"), "--skip", "~/.config/solana/id.json")
	if code != 0 || strings.Contains(out, "DV-201") || strings.Contains(out, "DV-204") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"--skip으로 뺀 경로(보지 않음)", "~/Documents/repo", "~/.config/solana/id.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if code, _, _ := runCLI(t, "device", "wallets", "--home", home, "--skip", ""); code != 2 {
		t.Errorf("empty --skip: code=%d", code)
	}
	if code, _, _ := runCLI(t, "device", "--home", home, "--skip", home); code != 2 {
		t.Errorf("--skip without wallets: code=%d", code)
	}
}

// The default phrase of a development tool in a project file is not a
// finding: the exit code stays 0 and the notes say so.
func TestDeviceWalletsPublicPhraseIsExit0(t *testing.T) {
	home := t.TempDir()
	devWrite(t, filepath.Join(home, "Documents", "dapp", ".env"), "MNEMONIC=\""+strings.Repeat("test ", 11)+"junk\"\n")
	code, out, errs := runCLI(t, "device", "wallets", "--home", home)
	if code != 0 || strings.Contains(out, "DV-201") || !strings.Contains(out, "공개 시험 문구만 있음: 글 파일 1개") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
}

// A folder named with --dir that is a link is a usage error: passing it by
// would leave the folder the user asked for unseen.
func TestDeviceWalletsDirThatIsALinkIsExit2(t *testing.T) {
	// Cleaned: mklink takes no '/' in a path.
	home, target := filepath.Clean(t.TempDir()), filepath.Clean(t.TempDir())
	devWrite(t, filepath.Join(target, "w.txt"), strings.Join(walletWords(t, 51, "english", 12), " "))
	link := filepath.Join(home, "notes")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Skip("cannot make a symbolic link here")
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Skipf("cannot make a junction here: %v (%d bytes of output)", err, len(out))
		}
	}
	code, out, errs := runCLI(t, "device", "wallets", "--home", home, "--dir", link)
	if code != 2 || out != "" || !strings.Contains(errs, "실제 위치") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if code, _, _ := runCLI(t, "device", "wallets", "--home", home, "--dir", target); code != 1 {
		t.Errorf("the real place: code=%d", code)
	}
	if runtime.GOOS != "windows" {
		return
	}
	// A junction made hidden and system, as Windows makes its own for old
	// programs, is a link all the same when the user names it.
	hidden := filepath.Join(home, "My Notes")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", hidden, target).CombinedOutput(); err != nil {
		t.Skipf("cannot make a junction here: %v (%d bytes of output)", err, len(out))
	}
	if out, err := exec.Command("attrib", "+h", "+s", "/l", hidden).CombinedOutput(); err != nil {
		t.Fatalf("attrib: %v (%d bytes of output)", err, len(out))
	}
	code, out, errs = runCLI(t, "device", "wallets", "--home", home, "--dir", hidden)
	if code != 2 || out != "" || !strings.Contains(errs, "실제 위치") {
		t.Fatalf("hidden system junction: code=%d\n%s\n%s", code, out, errs)
	}
}
