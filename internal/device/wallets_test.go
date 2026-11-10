package device

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func noEnv(string) string { return "" }

// asOS makes the check look where it looks on another system.
func asOS(t *testing.T, name string) {
	t.Helper()
	old := goos
	goos = name
	t.Cleanup(func() { goos = old })
}

func put(t *testing.T, body []byte, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// phrase is a seed phrase put together for this test run, as file content.
func phrase(seed int64, lang, n int) []byte {
	return []byte(strings.Join(phraseWords(rand.New(rand.NewSource(seed)), lang, n), " ") + "\n")
}

func wallets(t *testing.T, home string, dirs ...string) WalletResult {
	t.Helper()
	return CheckWallets(context.Background(), WalletOptions{Home: home, Getenv: noEnv, Dirs: dirs})
}

// byID lists the places of the findings with this id, sorted.
func byID(r WalletResult, id string) []string {
	var out []string
	for _, f := range r.Findings {
		if f.ID == id {
			out = append(out, f.Location)
		}
	}
	slices.Sort(out)
	return out
}

func wantPlaces(t *testing.T, r WalletResult, id string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := byID(r, id); !slices.Equal(got, want) {
		t.Errorf("%s at %q, want %q", id, got, want)
	}
}

const (
	metamaskID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
	phantomID  = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
	rabbyID    = "acmacodkjbdgmoleebolmdjonilkdbch"
)

func TestFindsWalletExtensionStores(t *testing.T) {
	for _, c := range []struct {
		os                  string
		chrome, edge, opera string
		firefox             string
	}{
		{"windows", "AppData/Local/Google/Chrome/User Data", "AppData/Local/Microsoft/Edge/User Data", "AppData/Roaming/Opera Software/Opera Stable",
			"AppData/Roaming/Mozilla/Firefox/Profiles"},
		{"darwin", "Library/Application Support/Google/Chrome", "Library/Application Support/Microsoft Edge", "Library/Application Support/com.operasoftware.Opera",
			"Library/Application Support/Firefox/Profiles"},
		{"linux", ".config/google-chrome", ".config/microsoft-edge", ".config/opera", ".mozilla/firefox"},
	} {
		t.Run(c.os, func(t *testing.T) {
			asOS(t, c.os)
			home := t.TempDir()
			at := func(rel ...string) string { return filepath.Join(append([]string{home}, rel...)...) }
			// Chrome: MetaMask in the first profile, Phantom (IndexedDB) in the second.
			mkdir(t, at(c.chrome, "Default", "Local Extension Settings", metamaskID))
			mkdir(t, at(c.chrome, "Default", "Local Extension Settings", strings.Repeat("a", 32)))
			mkdir(t, at(c.chrome, "Profile 1", "IndexedDB", "chrome-extension_"+phantomID+"_0.indexeddb.leveldb"))
			mkdir(t, at(c.chrome, "Profile 1", "IndexedDB", "https_example.test_0.indexeddb.leveldb"))
			// A file with a wallet's id is not a store.
			put(t, nil, at(c.chrome, "Profile 2", "Local Extension Settings", rabbyID))
			mkdir(t, at(c.edge, "Default", "Local Extension Settings", rabbyID))
			// Opera keeps its one profile in the folder itself.
			mkdir(t, at(c.opera, "Local Extension Settings", metamaskID))
			// Firefox names the store by a number prefs.js maps the add-on to.
			put(t, []byte("// prefs\nuser_pref(\"browser.x\", 1);\nuser_pref(\"extensions.webextensions.uuids\", \"{\\\"webextension@metamask.io\\\":\\\"0f0f0f0f-1111-2222-3333-444444444444\\\",\\\"other@example.test\\\":\\\"9a9a9a9a-1111-2222-3333-444444444444\\\"}\");\n"),
				at(c.firefox, "abcd.default-release", "prefs.js"))
			mkdir(t, at(c.firefox, "abcd.default-release", "storage", "default", "moz-extension+++0f0f0f0f-1111-2222-3333-444444444444^userContextId=4294967295"))
			mkdir(t, at(c.firefox, "abcd.default-release", "storage", "default", "moz-extension+++9a9a9a9a-1111-2222-3333-444444444444"))

			r := wallets(t, home)
			// The place of a finding is the profile folder.
			wantPlaces(t, r, "DV-202",
				"~/"+c.chrome+"/Default",
				"~/"+c.chrome+"/Profile 1",
				"~/"+c.edge+"/Default",
				"~/"+c.opera,
				"~/"+c.firefox+"/abcd.default-release",
			)
			if len(r.Unread) != 0 {
				t.Errorf("unread: %q", r.Unread)
			}
			for _, f := range r.Findings {
				if f.Severity != finding.Medium || f.Title == "" || f.ExplainKo == "" || f.Fix == "" || f.Source != Source {
					t.Errorf("finding at %s: severity %v, title %q, explain %d, fix %d", f.Location, f.Severity, f.Title, len(f.ExplainKo), len(f.Fix))
				}
			}
			var names []string
			for _, f := range r.Findings {
				names = append(names, f.Evidence)
			}
			for _, want := range []string{"Local Extension Settings/" + metamaskID, "IndexedDB/chrome-extension_" + phantomID + "_0.indexeddb.leveldb",
				"storage/default/moz-extension+++0f0f0f0f-1111-2222-3333-444444444444^userContextId=4294967295"} {
				if !strings.Contains(strings.Join(names, "\n"), want) {
					t.Errorf("no finding lists the folder %q: %q", want, names)
				}
			}
			for _, want := range []string{"MetaMask 확장 프로그램 저장소 (Chrome)", "Phantom 확장 프로그램 저장소 (Chrome)", "Rabby 확장 프로그램 저장소 (Edge)", "MetaMask 확장 프로그램 저장소 (Opera)", "MetaMask 확장 프로그램 저장소 (Firefox)"} {
				if !slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, want+". ") }) {
					t.Errorf("no finding says %q: %q", want, names)
				}
			}
		})
	}
}

func TestWindowsFollowsAppDataVariables(t *testing.T) {
	asOS(t, "windows")
	home, elsewhere := t.TempDir(), t.TempDir()
	mkdir(t, elsewhere, "Local", "Google", "Chrome", "User Data", "Default", "Local Extension Settings", metamaskID)
	put(t, []byte("x"), elsewhere, "Roaming", "Electrum", "wallets", "default_wallet")
	env := func(k string) string {
		return map[string]string{"LOCALAPPDATA": filepath.Join(elsewhere, "Local"), "APPDATA": filepath.Join(elsewhere, "Roaming")}[k]
	}
	r := CheckWallets(context.Background(), WalletOptions{Home: home, Getenv: env})
	if len(byID(r, "DV-202")) != 1 || len(byID(r, "DV-203")) != 1 {
		t.Errorf("findings: %q %q", byID(r, "DV-202"), byID(r, "DV-203"))
	}
}

func TestUnreadableFirefoxPrefsIsNotVerified(t *testing.T) {
	asOS(t, "linux")
	home := t.TempDir()
	put(t, []byte("user_pref(\"extensions.webextensions.uuids\", {broken);\n"), home, ".mozilla", "firefox", "p.default", "prefs.js")
	r := wallets(t, home)
	if len(r.Unread) != 1 || !strings.HasPrefix(r.Unread[0], "~/.mozilla/firefox/p.default/prefs.js: ") {
		t.Errorf("unread: %q", r.Unread)
	}
	// No add-on line at all: nothing installed, nothing unread.
	home = t.TempDir()
	put(t, []byte("user_pref(\"browser.x\", 1);\n"), home, ".mozilla", "firefox", "p.default", "prefs.js")
	if r := wallets(t, home); len(r.Unread) != 0 || len(r.Findings) != 0 {
		t.Errorf("unread %q, findings %d", r.Unread, len(r.Findings))
	}
}

func TestFindsDesktopWalletStores(t *testing.T) {
	for _, c := range []struct {
		os                                 string
		electrum, bitcoin, exodus, gethDir string
	}{
		{"windows", "AppData/Roaming/Electrum/wallets", "AppData/Roaming/Bitcoin", "AppData/Roaming/Exodus/exodus.wallet", "AppData/Local/Ethereum/keystore"},
		{"darwin", ".electrum/wallets", "Library/Application Support/Bitcoin", "Library/Application Support/Exodus/exodus.wallet", "Library/Ethereum/keystore"},
		{"linux", ".electrum/wallets", ".bitcoin", ".config/Exodus/exodus.wallet", ".ethereum/keystore"},
	} {
		t.Run(c.os, func(t *testing.T) {
			asOS(t, c.os)
			home := t.TempDir()
			put(t, []byte("x"), home, c.electrum, "default_wallet")
			put(t, []byte("x"), home, c.bitcoin, "wallet.dat")
			put(t, []byte("x"), home, c.exodus, "seed.seco")
			// An empty store holds nothing to take.
			mkdir(t, home, c.gethDir)
			mkdir(t, home, c.bitcoin, "wallets")
			put(t, []byte("[1,2,3]"), home, ".config", "solana", "id.json")
			r := wallets(t, home)
			wantPlaces(t, r, "DV-203", "~/"+c.electrum, "~/"+c.bitcoin+"/wallet.dat", "~/"+c.exodus)
			wantPlaces(t, r, "DV-204", "~/.config/solana/id.json")
			for _, f := range r.Findings {
				want := finding.Medium
				if f.ID == "DV-204" {
					want = finding.High
				}
				if f.Severity != want || f.ExplainKo == "" || f.Fix == "" {
					t.Errorf("%s at %s: severity %v, explain %d, fix %d", f.ID, f.Location, f.Severity, len(f.ExplainKo), len(f.Fix))
				}
			}
		})
	}
}

func TestFindsSeedPhraseFiles(t *testing.T) {
	asOS(t, "linux")
	home, other := t.TempDir(), t.TempDir()
	put(t, phrase(1, langEnglish, 12), home, "Documents", "notes", "wallet.txt")
	put(t, phrase(2, langEnglish, 24), home, "Desktop", "backup.md")
	put(t, phrase(3, langKorean, 12), home, "Downloads", "메모")
	put(t, phrase(4, langEnglish, 12), home, "top.txt")
	put(t, utf16LE(string(phrase(5, langEnglish, 12))), home, "Dropbox", "a", "b", "memo.TXT")
	put(t, phrase(6, langEnglish, 12), home, "문서", "지갑.txt")
	put(t, phrase(7, langEnglish, 12), other, "deep", "x.json")
	// Not looked at: another folder of the home folder, a picture, folders
	// of other people's files.
	put(t, phrase(8, langEnglish, 12), home, "projects", "x.txt")
	put(t, phrase(9, langEnglish, 12), home, "Documents", "photo.png")
	put(t, phrase(10, langEnglish, 12), home, "Documents", "repo", ".git", "x.txt")
	put(t, phrase(11, langEnglish, 12), home, "Documents", "repo", "node_modules", "p", "x.txt")
	// Ordinary files, and the word list itself.
	put(t, []byte("오늘 할 일: 장보기, 운동.\nremember to call the bank about the account\n"), home, "Documents", "todo.txt")
	put(t, []byte(bip39English), home, "Documents", "english.txt")
	put(t, []byte(bip39Korean), home, "Documents", "korean.txt")

	r := wallets(t, home, other)
	wantPlaces(t, r, "DV-201",
		"~/Documents/notes/wallet.txt", "~/Desktop/backup.md", "~/Downloads/메모", "~/top.txt",
		"~/Dropbox/a/b/memo.TXT", "~/문서/지갑.txt", filepath.ToSlash(filepath.Join(other, "deep", "x.json")))
	if len(r.Unread) != 0 {
		t.Errorf("unread: %q", r.Unread)
	}
	for _, f := range r.Findings {
		if f.Severity != finding.Critical || f.Confidence != finding.Suspect || f.Evidence != seedEvidence || f.Line != 0 || f.ExplainKo == "" || f.Fix == "" {
			t.Errorf("finding at %s: %v %v %q line %d", f.Location, f.Severity, f.Confidence, f.Evidence, f.Line)
		}
	}
	notes := strings.Join(r.Notes, "\n")
	for _, want := range []string{"~/Documents", "~/Desktop", "~/Downloads", "~/Dropbox", "찾아본 범위 안에서 없음", "읽은 글 파일 10개"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}

func TestWindowsSearchesOneDriveAndKnownFolders(t *testing.T) {
	asOS(t, "windows")
	home, drive, moved := t.TempDir(), t.TempDir(), t.TempDir()
	put(t, phrase(1, langEnglish, 12), drive, "문서", "a.txt")
	put(t, phrase(2, langEnglish, 12), moved, "b.txt")
	// Documents inside OneDrive is both a known folder and part of OneDrive: one finding.
	docs := mkdir(t, drive, "Documents")
	put(t, phrase(3, langEnglish, 12), docs, "1", "2", "3", "4", "5", "6", "c.txt")
	env := func(k string) string { return map[string]string{"OneDrive": drive}[k] }
	r := CheckWallets(context.Background(), WalletOptions{Home: home, Getenv: env, KnownFolders: []string{moved, docs}})
	if got := byID(r, "DV-201"); len(got) != 3 {
		t.Errorf("found %d files: %q", len(got), got)
	}
}

func TestSeedSearchKeepsToItsLimits(t *testing.T) {
	asOS(t, "linux")
	set := func(t *testing.T, p *int, v int) {
		old := *p
		*p = v
		t.Cleanup(func() { *p = old })
	}
	set64 := func(t *testing.T, p *int64, v int64) {
		old := *p
		*p = v
		t.Cleanup(func() { *p = old })
	}
	t.Run("depth", func(t *testing.T) {
		set(t, &maxSeedDepth, 2)
		home := t.TempDir()
		put(t, phrase(1, langEnglish, 12), home, "Documents", "1", "2", "in.txt")
		put(t, phrase(2, langEnglish, 12), home, "Documents", "1", "2", "3", "out.txt")
		r := wallets(t, home)
		wantPlaces(t, r, "DV-201", "~/Documents/1/2/in.txt")
		if n := strings.Join(r.Notes, "\n"); !strings.Contains(n, "2단계보다 깊은 폴더 1개") {
			t.Errorf("notes: %s", n)
		}
		if len(r.Unread) != 0 {
			t.Errorf("unread: %q", r.Unread)
		}
	})
	t.Run("file size", func(t *testing.T) {
		set64(t, &maxSeedFile, 4096)
		home := t.TempDir()
		put(t, append(phrase(1, langEnglish, 12), []byte(strings.Repeat("x y z\n", 1000))...), home, "Documents", "big.txt")
		put(t, phrase(2, langEnglish, 12), home, "Documents", "small.txt")
		r := wallets(t, home)
		wantPlaces(t, r, "DV-201", "~/Documents/small.txt")
		if n := strings.Join(r.Notes, "\n"); !strings.Contains(n, "큰 글 파일 1개") {
			t.Errorf("notes: %s", n)
		}
	})
	t.Run("file count", func(t *testing.T) {
		set(t, &maxSeedFiles, 3)
		home := t.TempDir()
		for _, n := range []string{"a", "b", "c", "d", "e"} {
			put(t, []byte("hello\n"), home, "Documents", n+".txt")
		}
		r := wallets(t, home)
		if len(r.Unread) != 1 || !strings.Contains(r.Unread[0], "다 보지 못했습니다") {
			t.Errorf("unread: %q", r.Unread)
		}
		if n := strings.Join(r.Notes, "\n"); !strings.Contains(n, "읽은 글 파일 3개") {
			t.Errorf("notes: %s", n)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		set64(t, &maxSeedBytes, 10)
		home := t.TempDir()
		for _, n := range []string{"a", "b", "c"} {
			put(t, []byte("hello hello\n"), home, "Documents", n+".txt")
		}
		if r := wallets(t, home); len(r.Unread) != 1 {
			t.Errorf("unread: %q", r.Unread)
		}
	})
	t.Run("entries", func(t *testing.T) {
		set(t, &maxSeedEntries, 4)
		home := t.TempDir()
		for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
			put(t, []byte("x"), home, "Documents", n+".bin")
		}
		if r := wallets(t, home); len(r.Unread) != 1 {
			t.Errorf("unread: %q", r.Unread)
		}
	})
}

func TestSeedSearchDoesNotFollowLinks(t *testing.T) {
	asOS(t, "linux")
	home, outside := t.TempDir(), t.TempDir()
	target := put(t, phrase(1, langEnglish, 12), outside, "secret.txt")
	mkdir(t, home, "Documents")
	if err := os.Symlink(target, filepath.Join(home, "Documents", "link.txt")); err != nil {
		t.Skip("cannot make a symbolic link here")
	}
	if err := os.Symlink(outside, filepath.Join(home, "Documents", "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "Desktop")); err != nil {
		t.Fatal(err)
	}
	r := wallets(t, home)
	if len(r.Findings) != 0 || len(r.Unread) != 0 {
		t.Errorf("findings %q, unread %q", byID(r, "DV-201"), r.Unread)
	}
	if n := strings.Join(r.Notes, "\n"); !strings.Contains(n, "링크 3개") {
		t.Errorf("notes: %s", n)
	}
}

// letterWords are the words of a text as the phrase search sees them.
func letterWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(composed(s)), func(r rune) bool { return !unicode.IsLetter(r) })
}

// holdsPhrasePiece reports whether out has two words of the phrase next to
// each other, in the order the phrase has them.
func holdsPhrasePiece(out string, words []string) bool {
	got := letterWords(out)
	for i := 0; i+1 < len(got); i++ {
		for j := 0; j+1 < len(words); j++ {
			if got[i] == composed(words[j]) && got[i+1] == composed(words[j+1]) {
				return true
			}
		}
	}
	return false
}

// What the check gives back is the same whatever the phrase is: its words,
// their number, how many phrases a file has and where they stand in it leave
// no trace.
func TestResultDoesNotDependOnThePhrase(t *testing.T) {
	asOS(t, "linux")
	rnd := rand.New(rand.NewSource(7))
	short := phraseWords(rnd, langEnglish, 12)
	long := phraseWords(rnd, langEnglish, 24)
	korean := phraseWords(rnd, langKorean, 18)
	electrum := electrumWords(rnd)
	bodies := map[string]string{
		"12 words":     strings.Join(short, " "),
		"24 words":     "\n\n\n\n" + strings.Join(long, "\n"),
		"korean":       composed(strings.Join(korean, " ")),
		"electrum":     strings.Join(electrum, " "),
		"two phrases":  strings.Join(short, " ") + "\n--\n" + strings.Join(long, " ") + "\n",
		"with a label": "seed: " + strings.Join(long, ", ") + strings.Repeat("\n", 40),
	}
	var first []byte
	for name, body := range bodies {
		home := t.TempDir()
		put(t, []byte(body), home, "Documents", "memo.txt")
		r := wallets(t, home)
		if len(r.Findings) != 1 {
			t.Fatalf("%s: %d findings", name, len(r.Findings))
		}
		out, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, words := range [][]string{short, long, korean, electrum} {
			if holdsPhrasePiece(string(out), words) {
				t.Errorf("%s: the result holds two words of a phrase side by side", name)
			}
		}
		if first == nil {
			first = out
		} else if !reflect.DeepEqual(first, out) {
			t.Errorf("%s: the result differs from that of another phrase at the same place", name)
		}
	}
}
