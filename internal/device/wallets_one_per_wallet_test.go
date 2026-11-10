package device

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const chromeWin = "AppData/Local/Google/Chrome/User Data"

// threeStores makes the three folders one wallet extension keeps in a profile.
func threeStores(t *testing.T, home, profile, id string) {
	t.Helper()
	p := filepath.Join(home, filepath.FromSlash(chromeWin), profile)
	mkdir(t, p, "Local Extension Settings", id)
	mkdir(t, p, "IndexedDB", "chrome-extension_"+id+"_0.indexeddb.leveldb")
	mkdir(t, p, "IndexedDB", "chrome-extension_"+id+"_0.indexeddb.blob")
}

func findingsOf(r WalletResult, id string) (out []string) {
	for _, f := range r.Findings {
		if f.ID == id {
			out = append(out, f.Evidence)
		}
	}
	return out
}

// One wallet in one profile is one finding at the profile folder, however
// many folders the wallet keeps there; the folders are listed in the evidence.
func TestWalletInOneProfileIsOneFinding(t *testing.T) {
	asOS(t, "windows")
	home := t.TempDir()
	threeStores(t, home, "Default", metamaskID)
	r := wallets(t, home)
	wantPlaces(t, r, "DV-202", "~/"+chromeWin+"/Default")
	ev := strings.Join(findingsOf(r, "DV-202"), "\n")
	for _, want := range []string{
		"MetaMask 확장 프로그램 저장소 (Chrome)", "폴더 3개",
		"Local Extension Settings/" + metamaskID,
		"IndexedDB/chrome-extension_" + metamaskID + "_0.indexeddb.leveldb",
		"IndexedDB/chrome-extension_" + metamaskID + "_0.indexeddb.blob",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q: %s", want, ev)
		}
	}
	if strings.Contains(ev, home) || strings.Contains(ev, filepath.ToSlash(home)) {
		t.Errorf("evidence holds the home folder: %s", ev)
	}
}

func TestWalletInTwoProfilesIsTwoFindings(t *testing.T) {
	asOS(t, "windows")
	home := t.TempDir()
	threeStores(t, home, "Default", metamaskID)
	threeStores(t, home, "Profile 1", metamaskID)
	r := wallets(t, home)
	wantPlaces(t, r, "DV-202", "~/"+chromeWin+"/Default", "~/"+chromeWin+"/Profile 1")
	if r.Findings[0].Fingerprint == r.Findings[1].Fingerprint {
		t.Error("two profiles share a fingerprint")
	}
}

// Two wallets in one profile stay two findings; the two store ids of one
// wallet (MetaMask from the Chrome and the Edge store) are one.
func TestFindingsAreCountedPerWallet(t *testing.T) {
	asOS(t, "windows")
	home := t.TempDir()
	threeStores(t, home, "Default", metamaskID)
	threeStores(t, home, "Default", phantomID)
	threeStores(t, home, "Default", "ejbalbakoplchlghecdalmeeeajnimhm")
	r := wallets(t, home)
	ev := findingsOf(r, "DV-202")
	slices.Sort(ev)
	if len(ev) != 2 || !strings.HasPrefix(ev[0], "MetaMask ") || !strings.Contains(ev[0], "폴더 6개") || !strings.HasPrefix(ev[1], "Phantom ") {
		t.Errorf("findings: %q", ev)
	}
}

// The fingerprint names the wallet in the profile, not the folders found: a
// folder the browser adds later leaves it the same finding.
func TestWalletFingerprintOutlivesANewFolder(t *testing.T) {
	asOS(t, "windows")
	home := t.TempDir()
	mkdir(t, home, filepath.FromSlash(chromeWin), "Default", "Local Extension Settings", metamaskID)
	before := wallets(t, home).Findings[0].Fingerprint
	threeStores(t, home, "Default", metamaskID)
	if after := wallets(t, home).Findings[0].Fingerprint; after != before {
		t.Errorf("fingerprint changed: %s -> %s", before, after)
	}
}

// A skipped store folder is left out of the list; with every folder of a
// wallet skipped there is no finding.
func TestSkippedStoreFolderIsNotListed(t *testing.T) {
	asOS(t, "windows")
	home := t.TempDir()
	threeStores(t, home, "Default", metamaskID)
	profile := filepath.Join(home, filepath.FromSlash(chromeWin), "Default")
	r := CheckWallets(context.Background(), WalletOptions{Home: home, Getenv: noEnv, Skip: []string{filepath.Join(profile, "IndexedDB")}})
	ev := findingsOf(r, "DV-202")
	if len(ev) != 1 || !strings.Contains(ev[0], "폴더 1개") || strings.Contains(ev[0], "IndexedDB") {
		t.Errorf("findings: %q", ev)
	}
	r = CheckWallets(context.Background(), WalletOptions{Home: home, Getenv: noEnv, Skip: []string{profile}})
	if ev := findingsOf(r, "DV-202"); len(ev) != 0 {
		t.Errorf("skipped profile still reported: %q", ev)
	}
}

// One desktop wallet with files in two of its places is one finding at the
// first place; the other place is in the evidence.
func TestDesktopWalletWithTwoPlacesIsOneFinding(t *testing.T) {
	asOS(t, "linux")
	home := t.TempDir()
	put(t, []byte("x"), home, ".bitcoin", "wallet.dat")
	put(t, []byte("x"), home, ".bitcoin", "wallets", "main", "wallet.dat")
	put(t, []byte("x"), home, ".electrum", "wallets", "default_wallet")
	r := wallets(t, home)
	wantPlaces(t, r, "DV-203", "~/.bitcoin/wallet.dat", "~/.electrum/wallets")
	ev := strings.Join(findingsOf(r, "DV-203"), "\n")
	if !strings.Contains(ev, "Bitcoin Core 키 저장 위치") || !strings.Contains(ev, "~/.bitcoin/wallets") {
		t.Errorf("evidence: %s", ev)
	}
	if strings.Contains(ev, "Electrum 키 저장 위치.") {
		t.Errorf("a wallet with one place lists other places: %s", ev)
	}
	// Alone, the second place is the finding's place.
	home = t.TempDir()
	put(t, []byte("x"), home, ".bitcoin", "wallets", "main", "wallet.dat")
	wantPlaces(t, wallets(t, home), "DV-203", "~/.bitcoin/wallets")
}
