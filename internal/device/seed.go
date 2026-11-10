package device

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// The BIP39 word lists, as published in the bitcoin/bips repository
// (bip-0039/english.txt, bip-0039/korean.txt). A test checks the English one
// against its published SHA-256.
//
//go:embed wallets/bip39-english.txt
var bip39English string

//go:embed wallets/bip39-korean.txt
var bip39Korean string

const (
	langEnglish = iota
	langKorean
	langCount
)

// seedSizes are the lengths a BIP39 phrase can have.
var seedSizes = [...]int{12, 15, 18, 21, 24}

const (
	seedMin = 12
	// maxSeedRun: up to this many list words in a row are one phrase with a
	// few label words around it, or two or three phrases: every stretch of
	// them is tried. A longer run is tried only where a stretch starts at
	// the start of a line and ends at the end of one, which is how several
	// phrases are written under one another (a word, three words or a whole
	// phrase on a line).
	maxSeedRun = 72
	// maxSeedList: more list words in a row than forty phrases have are a
	// word list. Only a line that is exactly as long as a phrase is tried.
	maxSeedList = 40 * 24
	// maxSeedWord bounds a token: the longest list word is 8 letters in
	// English and 4 syllables (12 jamo, 36 bytes) in Korean.
	maxSeedWord = 48
)

// seedLabels are words written next to a number to count the words of a
// phrase ("Word 1:", "1번 낱말"). Next to a number they are passed over in
// the second look at a text. Some are list words themselves, which is why
// the first look keeps them.
var seedLabels = []string{"word", "words", "no", "nr", "num", "number", "단어", "낱말", "번", "번째", "째"}

// publicSeedHashes are the SHA-256 of phrases everyone knows: the defaults of
// development tools and the published BIP39 test vectors. A file that holds
// only these is not reported. The phrases themselves are not written here.
// Each hash is of the places of the words in their list (0 to 2047), two
// bytes each, high byte first: the same for the phrase of one entropy in any
// language, so that the Korean test vectors are covered with the English
// ones. They were worked out in memory from the word list: the vectors from
// their published entropy, the tool defaults from their words.
var publicSeedHashes = []string{
	"c93dc4f8508e3f3d8962dd029ec801c10756392ee18522534700cfc8d4bec06b", // Hardhat, Anvil default
	"66b394550d4fd2eaf0af67a696b9afe9da4818a4a80efa9c02575b5de6349173", // Ganache --deterministic default
	"c7cf766e239b2f7cbbb71d986040caf96a9cf05d94ded699dddd80c2c42bb159", // Truffle develop default (Truffle 4; later versions make one per user)
	// BIP39 test vectors (trezor/python-mnemonic vectors.json), by entropy:
	"15a5d8b3d24420a581820f31b0ba17c5f73196f3ab744a2c36e17c7361b8d76e", // 00 x16
	"7c3327ee5c3b65365ebe6e74629b5c25f6ab5487b8d2b0e7505bbd88fbebf121", // 7f x16
	"0aefcce6fc97eeb7bc3d045214ac88b524ac5fd8d4b3ca15503be378840846d5", // 80 x16
	"3d64d0b028fe163058bfd545707f4190b048f8b058d33dab1f95113a5a1ad871", // ff x16
	"d82ec3f6dc74e58776a47f9c7d01e8a57d49000ce27507c5489537d4f1785c58", // 00 x24
	"7f8df51e2a9ab6916fd1716354a5daa6f43d5c0b87ddeb691a2793ec4843e70d", // 7f x24
	"56b5da9d3c326d612ba1e20a76950fe77cc7f7a44fd0c592cd952dda2d0fa1f3", // 80 x24
	"ad539f6a4f639510c1fb9ce3d1d18fc85ecb0879b27b067179bc3ace63b8d630", // ff x24
	"4cfba9512e9e5430cbae0bfb038f89759b466fbfe0ddf6061badbe19cdb35ec9", // 00 x32
	"7d41983a120f1c99fda813a5aebe40196ba39037f12c866ba4a799801a5da7f3", // 7f x32
	"f954239daa843541afed75bfd04e7f71bbbc1a2b25210e6eee7b85beb4344528", // 80 x32
	"737ed96cc675db8546eefa6b31ccd115c90c218a74955daa02d47ca9095b6240", // ff x32
	"b8a153b5b3e1f7422be283b88daa06c53046437fa0a2412c05bb31adc183face", // 9e885d95...
	"1a3493ceb28c9ebf5d79668089dec0d1f5dc9025f9cef2e2dfebbffd79f542ea", // 6610b259...
	"66b28f02cd18eac8fb5f29a842e4cc2aeefe14499615c771e8fd631d7aefe981", // 68a79eac...
	"d05d91975fd059d1a782c0382ccfef335b977da37c3d5ca2a2508adb24e81023", // c0ba5a8e...
	"bae484ece06f4c25f908ce5817c881d74184a46d6f9592fb586c7138ec055da5", // 6d9be1ee...
	"de8a42632bde95725bc4464dc2512e50056e9d14d0ddcacadf8aa02079ad2b91", // 9f6a2878...
	"a661fac75cbb4546590b54bd4b6f90d2bacb59307c432b3e4591ff2189d68608", // 23db8160...
	"46b4e1634df76c007a997c0a77c0209d6a225d5feedc628c821211e760bd1ad8", // 8197a4a4...
	"2e1e0399c4f27debf480bb07d629b9e9ffa5481c05588a7408695aefa4e4347f", // 066dca1a...
	"98867e1fd684bb38b36b61d8bebc7ee57f4345db813a7336bdb65e5208283be1", // f30f8c1d...
	"9ff262c1cb44616e688faf2f03e43a87d81b6a55be645917f6efaeef3a97b871", // c10ec20d...
	"6a8033a279600d4c31ba65726aec86e5bd59b06761711228eaf53454e859b177", // f585c11a...
}

type seedWordLists struct {
	// index maps a word to lang<<16 | place in its list. Korean words are
	// keyed in decomposed form (conjoining jamo), as the list is published.
	index map[string]uint32
	words [langCount][]string
	// labels are seedLabels, keyed like index.
	labels map[string]bool
	// public are publicSeedHashes.
	public map[[sha256.Size]byte]bool
}

var seedLists = sync.OnceValue(func() *seedWordLists {
	l := &seedWordLists{index: map[string]uint32{}, labels: map[string]bool{}, public: map[[sha256.Size]byte]bool{}}
	for lang, text := range [langCount]string{bip39English, bip39Korean} {
		l.words[lang] = strings.Fields(text)
		for i, w := range l.words[lang] {
			l.index[w] = uint32(lang)<<16 | uint32(i)
		}
	}
	for _, w := range seedLabels {
		var key []byte
		for _, r := range w {
			key = appendSeedRune(key, r)
		}
		l.labels[string(key)] = true
	}
	for _, h := range publicSeedHashes {
		var sum [sha256.Size]byte
		if b, err := hex.DecodeString(h); err == nil && len(b) == len(sum) {
			copy(sum[:], b)
			l.public[sum] = true
		}
	}
	return l
})

// seedTok is one list word met in a text: its place in the list and the line
// it is on.
type seedTok struct {
	v    uint16
	line int32
}

// seedResult is all a look at a text gives: which words, how many, where in
// the text and which checksum held are not passed on.
type seedResult int

const (
	seedNone seedResult = iota
	// seedPublicOnly: every phrase in the text is one everyone knows.
	seedPublicOnly
	seedFound
)

// hasSeedPhrase reports whether text holds what looks like a wallet seed
// phrase that is not one of the published test phrases.
func hasSeedPhrase(text []byte) bool { return seedLook(text) == seedFound }

// seedLook looks for what looks like a wallet seed phrase: at least 12
// words of one BIP39 list in a row, with nothing but digits, punctuation,
// line ends and counting marks ("1st", "1번") between them, of which 12, 15,
// 18, 21 or 24 pass a checksum. The text is looked at twice: as it is, and
// with counting words next to a number ("Word 1:") passed over.
func seedLook(text []byte) seedResult {
	r := seedScan(text, false)
	if r == seedFound {
		return r
	}
	return max(r, seedScan(text, true))
}

// isSeedLetter: r is a letter a list word can have.
func isSeedLetter(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= 0xAC00 && r <= 0xD7A3 || r >= 0x1100 && r <= 0x11FF
}

// appendSeedRune adds a letter to a token the way the lists are keyed: Latin
// letters in lower case, a Hangul syllable taken apart into its jamo.
func appendSeedRune(b []byte, r rune) []byte {
	switch {
	case r >= 'A' && r <= 'Z':
		return append(b, byte(r+'a'-'A'))
	case r >= 0xAC00 && r <= 0xD7A3:
		s := r - 0xAC00
		b = utf8.AppendRune(b, 0x1100+s/588)
		b = utf8.AppendRune(b, 0x1161+s%588/28)
		if t := s % 28; t != 0 {
			b = utf8.AppendRune(b, 0x11A7+t)
		}
		return b
	}
	return utf8.AppendRune(b, r)
}

func seedScan(text []byte, labels bool) seedResult {
	lists := seedLists()
	var (
		run     []seedTok
		runLang = -1
		buf     [maxSeedWord]byte
		word    = buf[:0]
		inWord  bool
		other   bool // the token has a letter no list word has, or is too long
		// byDigit: a digit stands right before or after the token ("1st",
		// "word1", "1번"): a counting mark, passed over.
		byDigit bool
		// sinceDigit: a digit came on this line since the last token that
		// was taken as a word or broke the run.
		sinceDigit bool
		// counted: the number last read already has its counting word, so
		// that the same word after it is a word of the phrase ("Word 5: word").
		counted bool
		// held: a counting word was read and it is not yet known whether it
		// counts: before a number ("Word 1: x") it does when the number
		// follows; after one ("1번 낱말: x", heldAfter) it does when a word
		// follows on the line, and is the word itself when the line ends.
		held      bool
		heldAfter bool
		heldV     uint32
		heldOK    bool
		heldLine  int32
		prev      rune
		line      int32
		result    = seedNone
	)
	defer func() {
		clear(run[:cap(run)])
		clear(buf[:])
	}()
	endRun := func() {
		found, public := seedRun(runLang, run)
		switch {
		case found:
			result = seedFound
		case public && result == seedNone:
			result = seedPublicOnly
		}
		clear(run)
		run, runLang = run[:0], -1
	}
	take := func(v uint32, ok bool, at int32) {
		sinceDigit = false
		if !ok {
			endRun()
			return
		}
		if lang := int(v >> 16); lang != runLang {
			endRun()
			runLang = lang
		}
		run = append(run, seedTok{v: uint16(v), line: at})
	}
	// settle decides a held counting word by what follows it: passed over
	// when it counts, a word like any other when not.
	const (
		thenWord = iota
		thenNumber
		thenLineEnd
	)
	settle := func(then int) {
		if !held {
			return
		}
		held = false
		if then == thenNumber || heldAfter && then == thenWord {
			counted = true
		} else {
			take(heldV, heldOK, heldLine)
		}
	}
	endWord := func(next rune) {
		if !inWord {
			return
		}
		inWord = false
		if unicode.IsDigit(next) {
			byDigit = true
		}
		v, ok := lists.index[string(word)]
		isLabel := labels && !other && lists.labels[string(word)]
		ok = ok && !other
		word, other = word[:0], false
		switch {
		case byDigit:
			// Passed over: neither a word nor the end of a run.
		case isLabel:
			held, heldAfter, heldV, heldOK, heldLine = true, sinceDigit && !counted, v, ok, line
		default:
			take(v, ok, line)
		}
		byDigit = false
	}
	eachRune(text, func(r rune) bool {
		switch {
		case isSeedLetter(r) || unicode.IsLetter(r):
			if !inWord {
				settle(thenWord)
				inWord, byDigit = true, unicode.IsDigit(prev)
			}
			switch {
			case !isSeedLetter(r) || len(word)+9 > cap(word):
				other = true
			default:
				word = appendSeedRune(word, r)
			}
		default:
			endWord(r)
			switch {
			case unicode.IsDigit(r):
				if !unicode.IsDigit(prev) && !held {
					counted = false
				}
				settle(thenNumber)
				sinceDigit = true
			case r == '\n':
				settle(thenLineEnd)
				sinceDigit, counted = false, false
				line++
			}
		}
		prev = r
		return result != seedFound
	})
	endWord(0)
	settle(thenLineEnd)
	endRun()
	return result
}

// eachRune calls f with every character of text: UTF-16 when text starts
// with its byte order mark (as Windows Notepad's "Unicode" does), UTF-8
// otherwise. It stops when f returns false.
func eachRune(text []byte, f func(rune) bool) {
	var le bool
	switch {
	case len(text) >= 2 && text[0] == 0xFF && text[1] == 0xFE:
		le = true
	case len(text) >= 2 && text[0] == 0xFE && text[1] == 0xFF:
	default:
		for i := 0; i < len(text); {
			r, size := utf8.DecodeRune(text[i:])
			i += size
			if !f(r) {
				return
			}
		}
		return
	}
	unit := func(i int) rune {
		if le {
			return rune(text[i]) | rune(text[i+1])<<8
		}
		return rune(text[i])<<8 | rune(text[i+1])
	}
	for i := 2; i+1 < len(text); i += 2 {
		r := unit(i)
		if utf16.IsSurrogate(r) && i+3 < len(text) {
			if full := utf16.DecodeRune(r, unit(i+2)); full != unicode.ReplacementChar {
				r = full
				i += 2
			}
		}
		if !f(r) {
			return
		}
	}
}

// seedRun looks at a run of list words. found: it holds a phrase that is not
// a published one. public: it holds a published one.
func seedRun(lang int, run []seedTok) (found, public bool) {
	if len(run) < seedMin {
		return false, false
	}
	aligned, exact := len(run) > maxSeedRun, len(run) > maxSeedList
	// tried: the stretch of size words from i is one to try.
	tried := func(i, size int) bool {
		if !aligned {
			return true
		}
		if i > 0 && run[i-1].line == run[i].line {
			return false
		}
		if end := i + size; end < len(run) && run[end].line == run[end-1].line {
			return false
		}
		return !exact || run[i].line == run[i+size-1].line
	}
	// A published phrase is set aside with its words, so that a stretch
	// that takes in some of them and passes a checksum by chance is not
	// reported in its place.
	type span struct{ from, to int }
	var known, hits []span
	for _, size := range seedSizes {
		for i := 0; i+size <= len(run); i++ {
			if !tried(i, size) {
				continue
			}
			w := run[i : i+size]
			valid := bip39Valid(w)
			switch {
			case valid && publicSeed(w):
				known = append(known, span{i, i + size})
			case seedWindow(lang, w, valid):
				if hits = append(hits, span{i, i + size}); len(known) == 0 && len(hits) > 1 {
					// One is enough until a published phrase turns up.
					hits = hits[:1]
				}
			}
		}
	}
	if len(known) == 0 {
		return len(hits) > 0, false
	}
	// With a published phrase in the run, the first hit alone may be one
	// that overlaps it: look again, keeping all.
	hits = hits[:0]
	for _, size := range seedSizes {
		for i := 0; i+size <= len(run); i++ {
			if w := run[i : i+size]; tried(i, size) && seedWindow(lang, w, bip39Valid(w)) && !publicSeed(w) {
				hits = append(hits, span{i, i + size})
			}
		}
	}
	for _, h := range hits {
		apart := true
		for _, k := range known {
			if h.from < k.to && k.from < h.to {
				apart = false
				break
			}
		}
		if apart {
			return true, true
		}
	}
	return false, true
}

// seedWindow reports whether exactly these words are a phrase: not a piece
// of a dictionary, not a phrase of one word over and over, and a checksum
// holds. valid is whether the BIP39 checksum holds.
func seedWindow(lang int, w []seedTok, valid bool) bool {
	// Words in list order, up or down, are a piece of a sorted word list.
	up, down := true, true
	for i := 1; i < len(w); i++ {
		if w[i].v < w[i-1].v {
			up = false
		}
		if w[i].v > w[i-1].v {
			down = false
		}
	}
	if up || down {
		return false
	}
	// A real phrase hardly ever repeats a word; made-up ones for tests
	// ("all all all ...") repeat most of theirs.
	distinct := 0
	for i := range w {
		seen := false
		for j := 0; j < i; j++ {
			if w[j].v == w[i].v {
				seen = true
				break
			}
		}
		if !seen {
			distinct++
		}
	}
	if distinct < len(w)-2 {
		return false
	}
	return valid || lang == langEnglish && len(w) == 12 && electrumValid(w)
}

// bip39Valid reports whether the words pass the BIP39 checksum: each word is
// 11 bits, and the last len/3 bits are the start of the SHA-256 of the rest.
func bip39Valid(w []seedTok) bool {
	var buf [33]byte
	defer clear(buf[:])
	bit := 0
	for _, t := range w {
		for b := 10; b >= 0; b-- {
			if t.v>>b&1 == 1 {
				buf[bit/8] |= 1 << (7 - bit%8)
			}
			bit++
		}
	}
	ent, cs := len(w)*4/3, len(w)/3
	sum := sha256.Sum256(buf[:ent])
	mask := byte(0xFF << (8 - cs))
	return buf[ent]&mask == sum[0]&mask
}

// seedText writes English words as a phrase is written: in lower case with
// one space between them. buf must hold 9 bytes a word.
func seedText(buf []byte, w []seedTok) []byte {
	words := seedLists().words[langEnglish]
	buf = buf[:0]
	for i, t := range w {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = append(buf, words[t.v]...)
	}
	return buf
}

// publicSeed reports whether the words are a phrase everyone knows, in
// whichever language they are written.
func publicSeed(w []seedTok) bool {
	var buf [24 * 2]byte
	defer clear(buf[:])
	for i, t := range w {
		buf[2*i], buf[2*i+1] = byte(t.v>>8), byte(t.v)
	}
	return seedLists().public[sha256.Sum256(buf[:2*len(w)])]
}

// electrumValid reports whether 12 English words are an Electrum seed (since
// Electrum 2.0): the HMAC-SHA512 of the phrase under the key "Seed version"
// starts, in hex, with 01 (standard), 100 (segwit), 101 or 102 (2FA), as in
// Electrum's mnemonic.py and version.py.
func electrumValid(w []seedTok) bool {
	var buf [12 * 9]byte
	defer clear(buf[:])
	sum := seedVersionMAC(seedText(buf[:], w))
	return sum[0] == 0x01 || sum[0] == 0x10 && sum[1]>>4 <= 2
}

func seedVersionMAC(phrase []byte) []byte {
	mac := hmac.New(sha512.New, []byte("Seed version"))
	mac.Write(phrase)
	return mac.Sum(nil)
}
