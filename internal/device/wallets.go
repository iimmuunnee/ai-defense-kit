package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// How much the search for seed phrases reads. Variables so that tests can
// lower them.
var (
	// maxSeedFile: a larger text file is not read (counted in the notes).
	maxSeedFile int64 = 1 << 20
	// maxSeedDepth: folders this far below a searched folder are not entered.
	maxSeedDepth = 6
	// Beyond these the search stops and says it did not see everything.
	maxSeedFiles         = 20000
	maxSeedBytes   int64 = 256 << 20
	maxSeedEntries       = 200000
)

// seedExts are the file name endings read as text. "" is a name with none.
var seedExts = map[string]bool{
	"": true, ".txt": true, ".text": true, ".md": true, ".markdown": true, ".csv": true, ".tsv": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true, ".cfg": true, ".conf": true,
	".env": true, ".log": true, ".org": true, ".html": true, ".htm": true, ".xml": true, ".bak": true, ".old": true,
}

// seedSkipDirs are folders not entered: they hold other people's files, in
// great numbers.
var seedSkipDirs = map[string]bool{".git": true, "node_modules": true}

var walletTitles = map[string]string{
	"DV-201": "글 파일에 시드 문구로 보이는 낱말 줄이 적혀 있음",
	"DV-202": "브라우저 프로필에 지갑 확장 프로그램의 저장소가 있음",
	"DV-203": "데스크톱 지갑의 키 저장 위치에 파일이 있음",
	"DV-204": "잠그지 않고 저장하는 것이 기본인 키 파일이 있음",
}

var walletSeverities = map[string]finding.Severity{
	"DV-201": finding.Critical,
	"DV-202": finding.Medium,
	"DV-203": finding.Medium,
	"DV-204": finding.High,
}

// seedEvidence is all that is said about a seed phrase that was found: not
// its words, their number, the line, or which checksum held.
const seedEvidence = "시드 문구로 보이는 낱말 줄(검산 맞음)"

// WalletOptions say where CheckWallets looks.
type WalletOptions struct {
	Home   string
	Getenv func(string) string
	// Dirs are more folders to search for seed phrases in text files.
	Dirs []string
	// Skip are files and folders left out: nothing at or under them is
	// read or reported.
	Skip []string
	// KnownFolders are the Desktop, Documents and Downloads folders as the
	// system tells them (they can be moved out of the home folder).
	KnownFolders []string
}

// WalletResult is what CheckWallets found. Nothing in it is a value read
// from a file, or a part, length or hash of one.
type WalletResult struct {
	Findings []finding.Finding
	// Unread: what is there but was not read, or not all of it.
	Unread []string
	// Notes say where the check looked and what it left out.
	Notes []string
}

// CheckWallets lists what a program that steals wallets could take from this
// computer: the stores of wallet extensions in browser profiles, the key
// stores of desktop wallets, and text files that hold what looks like a seed
// phrase. It reads only; a file's content stays in memory, is wiped after
// the look, and only "a phrase is there" leaves the function that read it.
func CheckWallets(ctx context.Context, o WalletOptions) WalletResult {
	if o.Getenv == nil {
		o.Getenv = func(string) string { return "" }
	}
	c := &walletCheck{ctx: ctx, home: o.Home, added: map[string]bool{}, seenDir: map[string]bool{}, links: map[string]bool{}}
	for _, p := range o.Skip {
		if p != "" {
			c.skip = append(c.skip, filepath.Clean(p))
		}
	}
	d := newAppDirs(o.Home, o.Getenv)
	c.extensions(d)
	c.desktopWallets(d)
	c.seedFiles(d, o)
	if c.unknown > 0 {
		c.unread = append(c.unread, fmt.Sprintf("글 파일 찾기: 종류를 알 수 없는 재분석 지점(특수 파일·폴더) %d개는 읽어도 되는지 판단하지 못해 읽지 않았습니다", c.unknown))
	}
	return WalletResult{Findings: c.findings, Unread: c.unread, Notes: c.notes()}
}

type walletCheck struct {
	ctx      context.Context
	home     string
	findings []finding.Finding
	added    map[string]bool
	unread   []string
	skip     []string

	browsers []string // browser folders that are there
	searched []string // folders searched for text files
	seenDir  map[string]bool
	// What the search for text files read and left out.
	files, large, deep, cloud int
	// unknown: entries of a kind that could not be told.
	unknown int
	// public: files whose every phrase is a published test phrase.
	public int
	// links are the links met and not followed, each counted once.
	links   map[string]bool
	entries int
	bytes   int64
	stopped bool
}

func (c *walletCheck) shown(p string) string { return Display(c.home, p) }

// skipped: path is one the user left out, or under one.
func (c *walletCheck) skipped(path string) bool {
	key := dirKey(filepath.Clean(path))
	for _, s := range c.skip {
		if k := dirKey(s); key == k || strings.HasPrefix(key, strings.TrimSuffix(k, string(filepath.Separator))+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// add reports one finding at path. what names the thing found there and,
// with the place, is what the fingerprint is made of; evidence is what the
// report shows.
func (c *walletCheck) add(id, path, what, evidence string) {
	if c.skipped(path) {
		return
	}
	loc := c.shown(path)
	fp := finding.MakeFingerprint(id, loc, what)
	if c.added[fp] {
		return
	}
	c.added[fp] = true
	conf := finding.Certain
	if id == "DV-201" {
		// The words pass a checksum; whether a wallet in use is behind them
		// is not known.
		conf = finding.Suspect
	}
	c.findings = append(c.findings, finding.Finding{
		ID:          id,
		Kind:        id,
		Source:      Source,
		Severity:    walletSeverities[id],
		Confidence:  conf,
		Location:    loc,
		Evidence:    evidence,
		Title:       walletTitles[id],
		ExplainKo:   readText("explain/" + id + ".md"),
		Fix:         readText("fixes/" + id + "/device.md"),
		Fingerprint: fp,
	})
}

func (c *walletCheck) miss(path, why string) {
	if c.skipped(path) {
		return
	}
	c.unread = append(c.unread, c.shown(path)+": "+why)
}

// list reads the names in a folder. A folder that is not there is empty; one
// that cannot be read is noted as unread.
func (c *walletCheck) list(dir string) []fs.DirEntry {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil:
		return entries
	case errors.Is(err, fs.ErrPermission):
		c.miss(dir, "폴더를 읽을 권한이 없습니다")
	case !errors.Is(err, fs.ErrNotExist) && isDir(dir):
		c.miss(dir, "폴더를 읽지 못했습니다")
	}
	return nil
}

// isDir: path is a folder itself, not a link to one.
func isDir(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.IsDir()
}

// What DirState says of a path the user named.
const (
	DirPlain     = iota // a folder that can be searched
	DirLink             // a symbolic link or, on Windows, a junction of any kind
	DirCloudOnly        // a folder whose listing is not on this disk
	DirOther            // not a folder, or of a kind that cannot be told
)

// DirState tells whether the folder at path, itself and not what a link
// there stands for, can be searched.
func DirState(path string) int {
	st, err := os.Lstat(path)
	switch {
	case err != nil:
		return DirOther
	case linkOf(path, st):
		return DirLink
	}
	switch kindOf(path, st) {
	case kindDir:
		return DirPlain
	case kindLink:
		return DirLink
	case kindCloudOnly:
		return DirCloudOnly
	}
	return DirOther
}

// extensions looks for the stores of wallet extensions. Only folder names
// are read; nothing inside a store is opened.
func (c *walletCheck) extensions(d appDirs) {
	for _, root := range chromiumRoots(d) {
		if !isDir(root.path) {
			continue
		}
		c.browsers = append(c.browsers, c.shown(root.path))
		profiles := []string{root.path}
		for _, e := range c.list(root.path) {
			if e.IsDir() {
				profiles = append(profiles, filepath.Join(root.path, e.Name()))
			}
		}
		for _, p := range profiles {
			var found profileStores
			les := filepath.Join(p, "Local Extension Settings")
			for _, e := range c.list(les) {
				if name, ok := walletExtensions[e.Name()]; ok && e.IsDir() {
					found.put(name, filepath.Join(les, e.Name()))
				}
			}
			idb := filepath.Join(p, "IndexedDB")
			for _, e := range c.list(idb) {
				id, ok := strings.CutPrefix(e.Name(), "chrome-extension_")
				id, _, _ = strings.Cut(id, "_")
				if name := walletExtensions[id]; ok && name != "" && e.IsDir() {
					found.put(name, filepath.Join(idb, e.Name()))
				}
			}
			c.addStores(p, root.name, found)
		}
	}
	for _, root := range firefoxRoots(d) {
		if !isDir(root.path) {
			continue
		}
		c.browsers = append(c.browsers, c.shown(root.path))
		for _, e := range c.list(root.path) {
			if e.IsDir() {
				c.firefoxProfile(filepath.Join(root.path, e.Name()))
			}
		}
	}
}

// profileStores are the store folders found in one browser profile, by
// wallet, in the order the wallets were first met.
type profileStores struct {
	wallets []string
	folders map[string][]string
}

func (s *profileStores) put(wallet, folder string) {
	if s.folders == nil {
		s.folders = map[string][]string{}
	}
	if _, ok := s.folders[wallet]; !ok {
		s.wallets = append(s.wallets, wallet)
	}
	s.folders[wallet] = append(s.folders[wallet], folder)
}

// addStores reports each wallet found in one profile once, at the profile
// folder: a wallet keeps several folders there and they are one thing to
// take. The folders are listed in the evidence, as paths below the profile.
// The fingerprint is of the wallet in the profile, not of the folders found.
func (c *walletCheck) addStores(profile, browser string, found profileStores) {
	for _, wallet := range found.wallets {
		var rel []string
		for _, f := range found.folders[wallet] {
			if c.skipped(f) {
				continue
			}
			r, err := filepath.Rel(profile, f)
			if err != nil {
				r = filepath.Base(f)
			}
			rel = append(rel, filepath.ToSlash(r))
		}
		if len(rel) == 0 {
			continue
		}
		what := wallet + " 확장 프로그램 저장소 (" + browser + ")"
		c.add("DV-202", profile, what, fmt.Sprintf("%s. 이 프로필에서 찾은 폴더 %d개: %s", what, len(rel), strings.Join(rel, ", ")))
	}
}

// firefoxProfile finds the stores of wallet add-ons in one Firefox profile.
// Firefox names an add-on's store by a number of its own, which prefs.js
// maps the add-on to.
func (c *walletCheck) firefoxProfile(p string) {
	prefs := filepath.Join(p, "prefs.js")
	b, err := readRegular(prefs, maxFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		c.miss(prefs, err.Error())
		return
	}
	uuids, err := firefoxUUIDs(b)
	if err != nil {
		c.miss(prefs, err.Error())
		return
	}
	store := filepath.Join(p, "storage", "default")
	var stores []fs.DirEntry
	var found profileStores
	for _, id := range sortedNames(firefoxWallets) {
		u := uuids[id]
		if u == "" {
			continue
		}
		if stores == nil {
			stores = c.list(store)
		}
		for _, e := range stores {
			if e.IsDir() && strings.HasPrefix(e.Name(), "moz-extension+++"+u) {
				found.put(firefoxWallets[id], filepath.Join(store, e.Name()))
			}
		}
	}
	c.addStores(p, "Firefox", found)
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firefoxUUIDs reads the add-on id to store number map out of prefs.js:
// user_pref("extensions.webextensions.uuids", "{\"<id>\":\"<number>\"}");
// No such line means no add-ons.
func firefoxUUIDs(prefs []byte) (map[string]string, error) {
	const key = `user_pref("extensions.webextensions.uuids",`
	for _, line := range strings.Split(string(prefs), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), key)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ";"))
		text, err := strconv.Unquote(strings.TrimSpace(strings.TrimSuffix(rest, ")")))
		if err != nil {
			return nil, errFormat
		}
		var m map[string]string
		if json.Unmarshal([]byte(text), &m) != nil {
			return nil, errFormat
		}
		return m, nil
	}
	return nil, nil
}

// desktopWallets looks whether the key stores of desktop wallets are there.
// Nothing in them is opened. A wallet with files in several of its places
// (Bitcoin Core: wallet.dat and wallets) is one finding at the first of
// them; the others are listed in the evidence.
func (c *walletCheck) desktopWallets(d appDirs) {
	type found struct {
		id, path, what string
		others         []string
	}
	var order []*found
	byWallet := map[string]*found{}
	for _, w := range walletPlaces(d) {
		st, err := os.Lstat(w.path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				c.miss(w.path, "볼 권한이 없습니다")
			}
			continue
		}
		if c.skipped(w.path) {
			continue
		}
		link := ""
		switch kindOf(w.path, st) {
		case kindLink:
			// A wallet's folder moved to another drive behind a link or a
			// junction is still there to take.
			link = ", 링크라서 따라가지 않음"
		case kindDir:
			if len(c.list(w.path)) == 0 {
				continue
			}
		case kindFile, kindCloudOnly:
		default:
			continue
		}
		key := w.id + "\x00" + w.name
		if f := byWallet[key]; f != nil {
			f.others = append(f.others, c.shown(w.path)+link)
			continue
		}
		what := " 키 저장 위치"
		if w.id == "DV-204" {
			what = " 키 파일 자리(잠그지 않고 저장하는 것이 기본)"
		}
		f := &found{id: w.id, path: w.path, what: w.name + what + link}
		byWallet[key] = f
		order = append(order, f)
	}
	for _, f := range order {
		evidence := f.what
		if len(f.others) > 0 {
			evidence += fmt.Sprintf(". 같은 지갑의 다른 위치 %d곳: %s", len(f.others), strings.Join(f.others, ", "))
		}
		c.add(f.id, f.path, f.what, evidence)
	}
}

// seedFiles searches the folders people keep notes in for text files that
// hold what looks like a seed phrase.
func (c *walletCheck) seedFiles(d appDirs, o WalletOptions) {
	// The home folder itself: its files only.
	if isDir(c.home) && !c.skipped(c.home) {
		c.searched = append(c.searched, c.shown(c.home)+"(바로 아래 파일만)")
		c.dir(c.home, -1)
	}
	var roots []string
	seen := map[string]bool{}
	for _, p := range append(append(textDirs(d, o.Getenv), o.KnownFolders...), o.Dirs...) {
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		st, err := os.Lstat(p)
		if seen[dirKey(p)] || err != nil || c.skipped(p) {
			continue
		}
		seen[dirKey(p)] = true
		switch kindOf(p, st) {
		case kindDir:
			roots = append(roots, p)
			c.searched = append(c.searched, c.shown(p))
		case kindLink:
			c.links[dirKey(p)] = true
		case kindCloudOnly:
			c.cloud++
		case kindUnknown:
			c.unknown++
		default:
			if linkOf(p, st) {
				c.links[dirKey(p)] = true
			}
		}
	}
	// A folder inside another searched folder goes first, so that it gets
	// its own full depth; the outer one then passes it by.
	order := append([]string(nil), roots...)
	sort.SliceStable(order, func(i, j int) bool { return len(order[i]) > len(order[j]) })
	for _, p := range order {
		c.dir(p, 0)
	}
}

// dirKey names a folder for "already searched": Windows and macOS file
// names do not tell upper case from lower.
func dirKey(p string) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(p)
	}
	return p
}

// dir searches one folder. depth is how far below the searched folder it
// is; -1 reads the files and enters no folder.
func (c *walletCheck) dir(path string, depth int) {
	if c.stopped {
		return
	}
	if depth >= 0 {
		if c.seenDir[dirKey(path)] {
			return
		}
		c.seenDir[dirKey(path)] = true
	}
	for _, e := range c.list(path) {
		if c.stopped {
			return
		}
		if c.ctx.Err() != nil {
			c.stopped = true
			return
		}
		if c.entries++; c.entries > maxSeedEntries {
			c.stop(fmt.Sprintf("폴더 항목이 %d개를 넘어", maxSeedEntries))
			return
		}
		t := e.Type()
		text := seedExts[strings.ToLower(filepath.Ext(e.Name()))]
		// What is plainly neither a text file, a folder nor something
		// special needs no closer look.
		if t.IsRegular() && !text {
			continue
		}
		child := filepath.Join(path, e.Name())
		if c.skipped(child) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue // gone since it was listed
		}
		// On Windows the type alone does not tell a link from a file
		// OneDrive keeps: the kind does.
		switch kindOf(child, fi) {
		case kindLink:
			// Not followed. In the home folder itself folders are not
			// entered anyway, so a link to one is nothing left out.
			if depth >= 0 || !linksToDir(fi) {
				c.links[dirKey(child)] = true
			}
		case kindCloudOnly, kindUnknown:
			// What would not have been read anyway is nothing left out: a
			// file that is no text file, a folder in the home folder itself.
			if fi.IsDir() && depth < 0 || !fi.IsDir() && !text {
				continue
			}
			if kindOf(child, fi) == kindCloudOnly {
				c.cloud++
			} else {
				c.unknown++
			}
		case kindDir:
			if depth < 0 || seedSkipDirs[e.Name()] {
				continue
			}
			if depth >= maxSeedDepth {
				c.deep++
				continue
			}
			c.dir(child, depth+1)
		case kindFile:
			if text {
				c.file(child)
			}
		}
	}
}

func (c *walletCheck) stop(why string) {
	c.stopped = true
	c.unread = append(c.unread, "글 파일 찾기: "+why+" 멈췄습니다. 찾아본 폴더를 다 보지 못했습니다. 파일이 많은 폴더(코드 저장소 등)를 --skip <폴더>로 빼고 다시 실행하세요. 뺀 폴더는 보지 않습니다")
}

// file looks at one text file.
func (c *walletCheck) file(path string) {
	if c.files >= maxSeedFiles {
		c.stop(fmt.Sprintf("글 파일이 %d개를 넘어", maxSeedFiles))
		return
	}
	if c.bytes >= maxSeedBytes {
		c.stop(fmt.Sprintf("읽은 양이 %dMiB를 넘어", maxSeedBytes>>20))
		return
	}
	b, err := readRegular(path, maxSeedFile)
	switch {
	case err == nil:
	case errors.Is(err, errTooLarge):
		c.large++
		return
	case errors.Is(err, errCloudOnly):
		c.cloud++
		return
	case errors.Is(err, errIsLink):
		c.links[dirKey(path)] = true
		return
	case errors.Is(err, errUnknownKind):
		c.unknown++
		return
	case errors.Is(err, fs.ErrNotExist):
		return
	default:
		c.miss(path, err.Error())
		return
	}
	c.files++
	c.bytes += int64(len(b))
	look := seedLook(b)
	clear(b)
	switch look {
	case seedFound:
		c.add("DV-201", path, seedEvidence, seedEvidence)
	case seedPublicOnly:
		c.public++
	}
}

var (
	errTooLarge    = errors.New("크기 한도보다 커서 읽지 않았습니다")
	errCloudOnly   = errors.New("클라우드에만 있는 파일이라 읽지 않았습니다")
	errIsLink      = errors.New("링크라서 따라가지 않았습니다")
	errUnknownKind = errors.New("종류를 알 수 없는 특수 파일이라 읽지 않았습니다")
)

// readRegular reads the file at path, at most max bytes of it. It does not
// follow a link, wait on a FIFO or fetch a file that is only in the cloud,
// and its errors are fixed sentences that quote nothing. The content is read
// into one buffer made for it, so that the caller's clear wipes all of it.
func readRegular(path string, max int64) ([]byte, error) {
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, openError(err)
	}
	switch kindOf(path, lst) {
	case kindFile:
	case kindLink:
		return nil, errIsLink
	case kindCloudOnly:
		return nil, errCloudOnly
	case kindUnknown:
		return nil, errUnknownKind
	default:
		return nil, errors.New("일반 파일이 아니어서 읽지 않았습니다")
	}
	if lst.Size() > max {
		return nil, errTooLarge
	}
	f, err := openRead(path)
	if err != nil {
		return nil, openError(err)
	}
	defer f.Close()
	// The file opened is the one looked at, not something put there since.
	// (A file OneDrive keeps is not "regular" to Go on Windows, so the kind
	// above decides and this only rules out folders and links.)
	st, err := f.Stat()
	if err != nil || st.IsDir() || st.Mode()&(fs.ModeSymlink|fs.ModeNamedPipe|fs.ModeDevice|fs.ModeSocket) != 0 || !os.SameFile(lst, st) {
		return nil, errIsLink
	}
	// A sync program may have sent the content away since the look above.
	if needsFetch(st) {
		return nil, errCloudOnly
	}
	b := make([]byte, lst.Size()+1)
	n, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		clear(b)
		if errors.Is(err, fs.ErrPermission) {
			return nil, errors.New("읽을 권한이 없습니다")
		}
		return nil, errors.New("파일을 읽지 못했습니다")
	}
	if int64(n) > max {
		clear(b)
		return nil, errTooLarge
	}
	return b[:n], nil
}

// notes say where the check looked and what it left out, so that "nothing
// found" is read as "nothing found in what was looked at".
func (c *walletCheck) notes() []string {
	var out []string
	if len(c.browsers) > 0 {
		out = append(out, "지갑 확장 프로그램 저장소를 찾아본 브라우저 폴더: "+strings.Join(c.browsers, ", "))
	} else {
		out = append(out, "아는 위치에서 브라우저 프로필 폴더를 찾지 못해 지갑 확장 프로그램 저장소는 보지 못했습니다.")
	}
	if len(c.searched) > 0 {
		out = append(out, fmt.Sprintf("시드 문구를 찾아본 폴더: %s. 읽은 글 파일 %d개.", strings.Join(c.searched, ", "), c.files))
	} else {
		out = append(out, "시드 문구를 찾아볼 폴더가 없었습니다.")
	}
	var left []string
	for _, s := range []struct {
		n    int
		what string
	}{
		{c.large, fmt.Sprintf("%dMiB보다 큰 글 파일 %%d개", maxSeedFile>>20)},
		{c.deep, fmt.Sprintf("%d단계보다 깊은 폴더 %%d개", maxSeedDepth)},
		{len(c.links), "링크 %d개(따라가지 않음)"},
		{c.cloud, "클라우드에만 있는 파일·폴더 %d개(내려받지 않음)"},
	} {
		if s.n > 0 {
			left = append(left, fmt.Sprintf(s.what, s.n))
		}
	}
	if len(left) > 0 {
		out = append(out, "읽지 않은 것: "+strings.Join(left, ", ")+". 그 안에 무엇이 있는지는 보지 못했습니다.")
	}
	if c.public > 0 {
		out = append(out, fmt.Sprintf("공개 시험 문구만 있음: 글 파일 %d개. 개발 도구의 기본 문구나 공개된 시험 벡터라서 알리지 않았습니다.", c.public))
	}
	if len(c.skip) > 0 {
		shown := make([]string, len(c.skip))
		for i, s := range c.skip {
			shown[i] = c.shown(s)
		}
		out = append(out, "--skip으로 뺀 경로(보지 않음): "+strings.Join(shown, ", "))
	}
	out = append(out, "결과에 없는 것은 '찾아본 범위 안에서 없음'입니다. 사진·PDF·문서 프로그램 파일·압축 파일·비밀번호 관리 프로그램 안, 목록에 없는 지갑과 브라우저, 다른 폴더는 보지 않았습니다.")
	return out
}
