//go:build windows

package device

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// junction makes link a junction to target, as mklink /J does. It needs no
// special rights.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot make a junction here: %v (%d bytes of output)", err, len(out))
	}
}

func TestJunctionIsNotFollowed(t *testing.T) {
	home, outside := filepath.Clean(t.TempDir()), filepath.Clean(t.TempDir())
	put(t, phrase(1, langEnglish, 12), outside, "secret.txt")
	put(t, []byte("x"), outside, "default_wallet")
	put(t, []byte("nothing\n"), home, "Documents", "plain.txt")
	junction(t, filepath.Join(home, "Documents", "elsewhere"), outside)
	// A searched folder that is itself a junction.
	junction(t, filepath.Join(home, "Desktop"), outside)
	// The kind Windows keeps in every home folder for old programs.
	old := filepath.Join(home, "My Documents")
	junction(t, old, filepath.Join(home, "Documents"))
	if out, err := exec.Command("attrib", "+h", "+s", "/l", old).CombinedOutput(); err != nil {
		t.Fatalf("attrib: %v (%d bytes of output)", err, len(out))
	}
	// A wallet folder moved to another drive behind a junction.
	mkdir(t, home, "AppData", "Roaming", "Electrum")
	junction(t, filepath.Join(home, "AppData", "Roaming", "Electrum", "wallets"), outside)

	if DirState(filepath.Join(home, "Desktop")) != DirLink || DirState(old) != DirLink || DirState(filepath.Join(home, "Documents")) != DirPlain {
		t.Error("DirState does not tell a junction, hidden or not, from a folder")
	}
	r := wallets(t, home)
	wantPlaces(t, r, "DV-201")
	wantPlaces(t, r, "DV-203", "~/AppData/Roaming/Electrum/wallets")
	if len(r.Unread) != 0 {
		t.Errorf("unread: %q", r.Unread)
	}
	notes := strings.Join(r.Notes, "\n")
	// Desktop and Documents\elsewhere; the old-program junction is not counted.
	if !strings.Contains(notes, "링크 2개") || !strings.Contains(notes, "읽은 글 파일 1개") {
		t.Errorf("notes: %s", notes)
	}
	for _, f := range r.Findings {
		if !strings.Contains(f.Evidence, "링크라서 따라가지 않음") {
			t.Errorf("evidence: %s", f.Evidence)
		}
	}
}
