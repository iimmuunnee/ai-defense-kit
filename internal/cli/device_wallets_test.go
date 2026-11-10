package cli

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// walletWords puts a seed phrase of n words together while the test runs,
// from the word list the device package builds in, with its checksum worked
// out here. No phrase is written in this file, and none is printed: a
// failure says where a piece was seen, never the piece.
func walletWords(t *testing.T, seed int64, list string, n int) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "device", "wallets", "bip39-"+list+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Fields(string(b))
	rnd := rand.New(rand.NewSource(seed))
	for {
		ent := make([]byte, n*4/3)
		var bits strings.Builder
		for i := range ent {
			ent[i] = byte(rnd.Intn(256))
			fmt.Fprintf(&bits, "%08b", ent[i])
		}
		sum := sha256.Sum256(ent)
		s := bits.String() + fmt.Sprintf("%08b", sum[0])[:n/3]
		words := make([]string, n)
		for i := range words {
			v, _ := strconv.ParseInt(s[i*11:i*11+11], 2, 32)
			words[i] = all[v]
		}
		u := slices.Clone(words)
		slices.Sort(u)
		if len(slices.Compact(u)) == n && !slices.IsSorted(words) {
			return words
		}
	}
}

// walletTextWords are the words of a text, as runs of letters in lower case.
func walletTextWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsMark(r) })
}

// walletNoPhrase fails when out holds two words of a planted phrase next to
// each other in the phrase's order.
func walletNoPhrase(t *testing.T, where, out string, phrases ...[]string) {
	t.Helper()
	got := walletTextWords(out)
	for _, words := range phrases {
		for i := 0; i+1 < len(got); i++ {
			for j := 0; j+1 < len(words); j++ {
				if got[i] == words[j] && got[i+1] == words[j+1] {
					t.Errorf("%s holds two words of a planted phrase side by side", where)
					return
				}
			}
		}
	}
}

// walletChrome is where Chrome keeps its profiles under home on this system.
func walletChrome(home string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
	}
	return filepath.Join(home, ".config", "google-chrome")
}

// walletFirefox is where Firefox keeps its profiles under home on this system.
func walletFirefox(home string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	}
	return filepath.Join(home, ".mozilla", "firefox")
}

const walletMetaMask = "nkbihfbeogaeaoehlefnkodbefgpgknn"

func walletStore(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(walletChrome(home), "Default", "Local Extension Settings", walletMetaMask), 0o755); err != nil {
		t.Fatal(err)
	}
}

func walletIDs(t *testing.T, out string) map[string]int {
	t.Helper()
	ids := map[string]int{}
	for _, f := range devFindings(t, out).Findings {
		ids[f.ID]++
	}
	return ids
}

func TestDeviceWalletsListsWhatCouldBeTaken(t *testing.T) {
	home := t.TempDir()
	devWrite(t, filepath.Join(home, "Documents", "memo.txt"), strings.Join(walletWords(t, 1, "english", 12), " ")+"\n")
	devWrite(t, filepath.Join(home, "Desktop", "지갑.md"), "복구용\n\n"+strings.Join(walletWords(t, 2, "english", 24), "\n")+"\n")
	devWrite(t, filepath.Join(home, ".config", "solana", "id.json"), "[]")
	devWrite(t, filepath.Join(home, "Documents", "todo.txt"), "buy milk and call the bank about the account\n")
	walletStore(t, home)

	code, out, errs := runCLI(t, "device", "wallets", "--home", home, "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s", code, errs)
	}
	if ids := walletIDs(t, out); ids["DV-201"] != 2 || ids["DV-202"] != 1 || ids["DV-204"] != 1 || len(ids) != 3 {
		t.Errorf("ids = %v", ids)
	}
	for _, f := range devFindings(t, out).Findings {
		if f.ID == "DV-201" && (f.Severity.String() != "critical" || f.Line != 0 || !strings.HasPrefix(f.Location, "~/")) {
			t.Errorf("DV-201: %v line %d at %s", f.Severity, f.Line, f.Location)
		}
	}
	// The plain device check does not look for wallets.
	_, out, _ = runCLI(t, "device", "--home", home, "--format", "json")
	if ids := walletIDs(t, out); len(ids) != 0 {
		t.Errorf("adk device reports %v", ids)
	}
}

// Using a wallet is not a failure: a store alone leaves the exit code at 0.
func TestDeviceWalletsStoreAloneIsExit0(t *testing.T) {
	home := t.TempDir()
	walletStore(t, home)
	code, out, errs := runCLI(t, "device", "wallets", "--home", home)
	if code != 0 || !strings.Contains(out, "DV-202") || !strings.Contains(out, "MetaMask") {
		t.Errorf("code=%d\n%s\n%s", code, out, errs)
	}
	if code, _, _ := runCLI(t, "device", "wallets", "--home", home, "--fail-on", "medium"); code != 1 {
		t.Errorf("--fail-on medium: code=%d", code)
	}
}

func TestDeviceWalletsNothingThere(t *testing.T) {
	home := t.TempDir()
	code, out, errs := runCLI(t, "device", "wallets", "--home", home)
	if code != 0 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"찾아본 범위 안에서 없음", "브라우저 프로필 폴더를 찾지 못해"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
	for _, bad := range []string{"안전", "막습니다", "막는다"} {
		if strings.Contains(out, bad) || strings.Contains(errs, bad) {
			t.Errorf("report says %q", bad)
		}
	}
}

var (
	walletTime = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T[0-9:.+Z-]+`)
	walletHash = regexp.MustCompile(`"sha256": "[0-9a-f]{64}"`)
)

// walletRun plants one file with body and returns everything the command
// wrote: stdout, stderr and each file under --out, by its ending.
func walletRun(t *testing.T, body string) map[string]string {
	t.Helper()
	// Cleaned: a TMP written with '/' on Windows gives a path of both kinds.
	home, dir := filepath.Clean(t.TempDir()), filepath.Clean(t.TempDir())
	devWrite(t, filepath.Join(home, "Documents", "memo.txt"), body)
	walletStore(t, home)
	code, out, errs := runCLI(t, "device", "wallets", "--home", home, "--format", "md,json,sarif", "--out", dir)
	if code != 1 {
		t.Fatalf("code=%d\n%s", code, errs)
	}
	all := map[string]string{"stdout": out, "stderr": errs}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Errorf("want 3 reports and an evidence file, got %d", len(entries))
	}
	for i, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), filepath.ToSlash(home)) || strings.Contains(string(b), home) {
			t.Errorf("%s holds the home folder path", e.Name())
		}
		text := string(b)
		if strings.Contains(e.Name(), "evidence") {
			// The evidence file holds the SHA-256 of each report file, which
			// changes with the time written in them. The reports themselves
			// are compared below with only that time taken out.
			text = walletHash.ReplaceAllString(text, `"sha256": "<report>"`)
		}
		all[fmt.Sprintf("file %d %s", i, filepath.Ext(e.Name()))] = text
	}
	_, out, errs = runCLI(t, "device", "wallets", "--home", home)
	all["md stdout"], all["md stderr"] = out, errs
	_, out, errs = runCLI(t, "device", "wallets", "--home", home, "--format", "json")
	all["json stdout"], all["json stderr"] = out, errs
	for k, v := range all {
		v = strings.ReplaceAll(strings.ReplaceAll(v, filepath.ToSlash(dir), "<out>"), dir, "<out>")
		all[k] = walletTime.ReplaceAllString(v, "<time>")
	}
	return all
}

// Nothing the command writes holds the phrase, and nothing it writes depends
// on the phrase: with other words, another number of words, more phrases in
// the file or other lines, every output is the same to the byte (the time of
// the run aside). So no part, length, count, line or hash of it gets out.
func TestDeviceWalletsNeverPrintsPhrase(t *testing.T) {
	short := walletWords(t, 11, "english", 12)
	long := walletWords(t, 12, "english", 24)
	korean := walletWords(t, 13, "korean", 18)
	bodies := []struct{ name, body string }{
		{"12 words", strings.Join(short, " ") + "\n"},
		{"24 words one per line", "\n\n\n" + strings.Join(long, "\r\n") + "\r\n"},
		{"korean", strings.Join(korean, " ")},
		{"two phrases and a label", "seed: " + strings.Join(short, ", ") + "\n--\n" + strings.Join(long, " ") + strings.Repeat("\n", 30)},
	}
	var first map[string]string
	for _, b := range bodies {
		got := walletRun(t, b.body)
		for where, text := range got {
			walletNoPhrase(t, b.name+": "+where, text, short, long, korean)
			if where != "stdout" && !strings.Contains(where, "stderr") && !strings.Contains(text, "DV-201") {
				t.Errorf("%s: %s lacks the finding", b.name, where)
			}
		}
		if first == nil {
			first = got
			continue
		}
		if len(got) != len(first) {
			t.Errorf("%s: %d outputs, the first run had %d", b.name, len(got), len(first))
		}
		for where, text := range got {
			if text != first[where] {
				t.Errorf("%s: %s differs from the run with another phrase", b.name, where)
			}
		}
	}
}

func TestDeviceWalletsDir(t *testing.T) {
	home, extra := t.TempDir(), t.TempDir()
	devWrite(t, filepath.Join(extra, "notes", "w.txt"), strings.Join(walletWords(t, 21, "english", 12), " "))
	if code, out, _ := runCLI(t, "device", "wallets", "--home", home, "--format", "json"); code != 0 || len(walletIDs(t, out)) != 0 {
		t.Errorf("without --dir: code=%d", code)
	}
	code, out, errs := runCLI(t, "device", "wallets", "--home", home, "--dir", extra, "--dir", home, "--format", "json")
	if code != 1 || walletIDs(t, out)["DV-201"] != 1 {
		t.Errorf("with --dir: code=%d\n%s", code, errs)
	}
	if strings.Contains(out, strings.Join(walletWords(t, 21, "english", 12)[:2], " ")) {
		t.Error("the report holds words of the phrase")
	}
}

func TestDeviceWalletsOptions(t *testing.T) {
	home := t.TempDir()
	for _, args := range [][]string{
		{"device", "wallets", "--home", home, "--dir", filepath.Join(home, "missing")},
		{"device", "wallets", "--home", home, "--dir", ""},
		{"device", "wallets", "--home", home, "--baseline", "x"},
		{"device", "wallets", "--home", home, "--path", "x"},
		{"device", "wallets", "--home", home, "--note", "x"},
		{"device", "wallets", "--home", home, "extra"},
		{"device", "--home", home, "--dir", home},
		{"device", "check", "--home", home, "--dir", home},
		{"device", "wallet", "--home", home},
	} {
		if code, out, _ := runCLI(t, args...); code != 2 || out != "" {
			t.Errorf("%v: code=%d, stdout %d bytes", args[1:], code, len(out))
		}
	}
	if code, out, _ := runCLI(t, "device", "--help"); code != 0 || !strings.Contains(out, "adk device wallets") {
		t.Errorf("help: code=%d", code)
	}
}

// A Firefox profile whose add-on list cannot be read was not verified.
func TestDeviceWalletsUnreadIsExit2(t *testing.T) {
	home := t.TempDir()
	devWrite(t, filepath.Join(walletFirefox(home), "p.default", "prefs.js"), "user_pref(\"extensions.webextensions.uuids\", {broken);\n")
	code, out, errs := runCLI(t, "device", "wallets", "--home", home)
	if code != 2 || !strings.Contains(out, "확인 못 함") || !strings.Contains(errs, "prefs.js") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	// A finding at or above --fail-on wins.
	devWrite(t, filepath.Join(home, ".config", "solana", "id.json"), "[]")
	if code, _, _ := runCLI(t, "device", "wallets", "--home", home); code != 1 {
		t.Errorf("finding and unread: code=%d", code)
	}
}

// A link is not followed: neither a linked file, nor a linked folder, nor a
// searched folder that is itself a link. They are counted in the notes.
func TestDeviceWalletsDoesNotFollowLinks(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	devWrite(t, filepath.Join(outside, "secret.txt"), strings.Join(walletWords(t, 31, "english", 12), " "))
	devWrite(t, filepath.Join(home, "Documents", "plain.txt"), "nothing here\n")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(home, "Documents", "link.txt")); err != nil {
		t.Skip("cannot make a symbolic link here")
	}
	for _, link := range []string{filepath.Join(home, "Documents", "linkdir"), filepath.Join(home, "Desktop")} {
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := runCLI(t, "device", "wallets", "--home", home)
	if code != 0 || strings.Contains(out, "DV-201") || !strings.Contains(out, "링크 3개") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
}

func TestDeviceWalletsUnreadableFolderIsExit2(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not deny reading on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read any folder")
	}
	home := t.TempDir()
	locked := filepath.Join(home, "Documents", "locked")
	devWrite(t, filepath.Join(locked, "a.txt"), "x")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	code, out, errs := runCLI(t, "device", "wallets", "--home", home)
	if code != 2 || !strings.Contains(out, "확인 못 함") || !strings.Contains(errs, "~/Documents/locked") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
}
