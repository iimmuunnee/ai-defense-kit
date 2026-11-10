package device

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkipLeavesOutFilesAndFolders(t *testing.T) {
	asOS(t, "linux")
	home := t.TempDir()
	put(t, phrase(1, langEnglish, 12), home, "Documents", "mine.txt")
	put(t, phrase(2, langEnglish, 12), home, "Documents", "repo", "docs", "example.md")
	put(t, phrase(3, langEnglish, 12), home, "Documents", "checked.txt")
	put(t, phrase(4, langEnglish, 12), home, "Documents", "repository.txt")
	key := put(t, []byte("[]"), home, ".config", "solana", "id.json")
	r := CheckWallets(context.Background(), WalletOptions{Home: home, Getenv: noEnv, Skip: []string{
		filepath.Join(home, "Documents", "repo"), filepath.Join(home, "Documents", "checked.txt"), key,
	}})
	// A name that only starts like a skipped one is still looked at.
	wantPlaces(t, r, "DV-201", "~/Documents/mine.txt", "~/Documents/repository.txt")
	wantPlaces(t, r, "DV-204")
	notes := strings.Join(r.Notes, "\n")
	for _, want := range []string{"--skip으로 뺀 경로(보지 않음)", "~/Documents/repo", "~/Documents/checked.txt", "~/.config/solana/id.json", "읽은 글 파일 2개"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}

// A file whose every phrase is a published test phrase is not a finding; the
// notes say how many such files there were.
func TestFileOfPublicPhrasesIsOnlyNoted(t *testing.T) {
	asOS(t, "linux")
	home := t.TempDir()
	public := strings.Repeat("test ", 11) + "junk"
	put(t, []byte("MNEMONIC=\""+public+"\"\n"), home, "Documents", "dapp", ".env")
	put(t, []byte("# local node\n\n    "+public+"\n"), home, "Documents", "dapp", "README.md")
	r := wallets(t, home)
	if len(r.Findings) != 0 || len(r.Unread) != 0 {
		t.Errorf("%d findings, unread %q", len(r.Findings), r.Unread)
	}
	if n := strings.Join(r.Notes, "\n"); !strings.Contains(n, "공개 시험 문구만 있음: 글 파일 2개") {
		t.Errorf("notes: %s", n)
	}
	// With a phrase of the user next to it the file is reported.
	put(t, append([]byte(public+"\n\n"), phrase(9, langEnglish, 12)...), home, "Documents", "both.txt")
	wantPlaces(t, wallets(t, home), "DV-201", "~/Documents/both.txt")
}
