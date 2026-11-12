package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// walletThreeStores makes the three folders MetaMask keeps in a Chrome profile.
func walletThreeStores(t *testing.T, home, profile string) {
	t.Helper()
	p := filepath.Join(walletChrome(home), profile)
	for _, d := range []string{
		filepath.Join("Local Extension Settings", walletMetaMask),
		filepath.Join("IndexedDB", "chrome-extension_"+walletMetaMask+"_0.indexeddb.leveldb"),
		filepath.Join("IndexedDB", "chrome-extension_"+walletMetaMask+"_0.indexeddb.blob"),
	} {
		if err := os.MkdirAll(filepath.Join(p, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// Two profiles with a wallet are two findings, and the Markdown report
// explains the finding once, lists both profiles under it and carries the
// notes on what was searched.
func TestDeviceWalletsReportsEachWalletOnce(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	walletThreeStores(t, home, "Default")
	walletThreeStores(t, home, "Profile 1")
	code, _, errs := runCLI(t, "device", "wallets", "--home", home, "--format", "md,json", "--out", dir)
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, errs)
	}
	js, err := os.ReadFile(filepath.Join(dir, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if ids := walletIDs(t, string(js)); ids["DV-202"] != 2 || len(ids) != 1 {
		t.Errorf("ids = %v", ids)
	}
	b, err := os.ReadFile(filepath.Join(dir, "adk-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	md := string(b)
	for _, once := range []string{"- 번호: DV-202", "왜 확인해야 하나요?", "**수정 방법**", "**해당 결과 2건**"} {
		if n := strings.Count(md, once); n != 1 {
			t.Errorf("%q is in the report %d times, want 1", once, n)
		}
	}
	for _, want := range []string{
		"/Default`\n", "/Profile 1`\n", "이 프로필에서 찾은 폴더 3개: Local Extension Settings/" + walletMetaMask,
		"> 참고\n", "지갑 확장 프로그램 저장소를 찾아본 브라우저 폴더: ", "시드 문구를 찾아본 폴더", "찾아본 범위 안에서 없음",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q\n%s", want, md)
		}
	}
	if strings.Contains(md, home) || strings.Contains(md, filepath.ToSlash(home)) {
		t.Error("the report holds the home folder's path")
	}
}
