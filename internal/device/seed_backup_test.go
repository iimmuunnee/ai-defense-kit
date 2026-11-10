package device

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// As in seed_test.go, every phrase here is put together while the test runs
// and none is printed.

// several returns count phrases of n words.
func several(rnd *rand.Rand, lang, count, n int) [][]string {
	out := make([][]string, count)
	for i := range out {
		out[i] = phraseWords(rnd, lang, n)
	}
	return out
}

// written writes each word of each phrase with line(i, word), i from 1, and
// between between two phrases.
func written(phrases [][]string, between string, line func(i int, w string) string) []byte {
	var b strings.Builder
	for k, p := range phrases {
		if k > 0 {
			b.WriteString(between)
		}
		for i, w := range p {
			b.WriteString(line(i+1, w))
		}
	}
	return []byte(b.String())
}

// The file worth most to a thief: the phrases of several wallets, written
// under one another.
func TestFindsSeveralPhrasesInOneFile(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	bare := func(_ int, w string) string { return w + "\n" }
	numbered := func(i int, w string) string { return fmt.Sprintf("%d. %s\n", i, w) }
	three := func(i int, w string) string {
		if i%3 == 0 {
			return w + "\n"
		}
		return w + " "
	}
	var headed strings.Builder
	for k, p := range several(rnd, langEnglish, 4, 24) {
		fmt.Fprintf(&headed, "Phrase %d:\n%s\n", k+1, written([][]string{p}, "", numbered))
	}
	cases := map[string][]byte{
		"four of 24 words, numbered, a word a line, an empty line between": written(several(rnd, langEnglish, 4, 24), "\n", numbered),
		"four of 24 words under a Phrase n: line":                          []byte(headed.String()),
		"seven of 12 words, a word a line, nothing between":                written(several(rnd, langEnglish, 7, 12), "", bare),
		"seven of 12 words, three words a line":                            written(several(rnd, langEnglish, 7, 12), "", three),
		"forty of 24 words, a word a line":                                 written(several(rnd, langEnglish, 40, 24), "", bare),
		"five Korean of 24 words, a word a line":                           []byte(composed(string(written(several(rnd, langKorean, 5, 24), "\n", numbered)))),
		"three of 24 words, a word a line":                                 written(several(rnd, langEnglish, 3, 24), "\n", bare),
	}
	for name, body := range cases {
		if !hasSeedPhrase(body) {
			t.Errorf("%s: not found", name)
		}
	}
}

// phraseWith returns a phrase of n English words that has word in it, away
// from both ends.
func phraseWith(rnd *rand.Rand, n int, word string) []string {
	for {
		if p := phraseWords(rnd, langEnglish, n); slices.Contains(p[1:n-1], word) {
			return p
		}
	}
}

func TestFindsPhraseWithCountedWords(t *testing.T) {
	rnd := rand.New(rand.NewSource(4))
	en := phraseWords(rnd, langEnglish, 12)
	ko := phraseWords(rnd, langKorean, 12)
	ordinal := func(i int) string {
		switch {
		case i%10 == 1 && i != 11:
			return "st"
		case i%10 == 2 && i != 12:
			return "nd"
		case i%10 == 3 && i != 13:
			return "rd"
		}
		return "th"
	}
	styles := map[string]func(i int, w string) string{
		"1st":           func(i int, w string) string { return fmt.Sprintf("%d%s %s\n", i, ordinal(i), w) },
		"1st: on a row": func(i int, w string) string { return fmt.Sprintf("%d%s: %s, ", i, ordinal(i), w) },
		"word1:":        func(i int, w string) string { return fmt.Sprintf("word%d: %s\n", i, w) },
		"Word 1:":       func(i int, w string) string { return fmt.Sprintf("Word %d: %s\n", i, w) },
		"Word #1 -":     func(i int, w string) string { return fmt.Sprintf("Word #%d - %s\n", i, w) },
		"No. 1":         func(i int, w string) string { return fmt.Sprintf("No. %d %s\n", i, w) },
		"1번":            func(i int, w string) string { return fmt.Sprintf("%d번 %s\n", i, w) },
		"1번째":           func(i int, w string) string { return fmt.Sprintf("%d번째: %s\n", i, w) },
		"1번 낱말":         func(i int, w string) string { return fmt.Sprintf("%d번 낱말: %s\n", i, w) },
		"단어 1:":         func(i int, w string) string { return fmt.Sprintf("단어 %d: %s\n", i, w) },
		"#1":            func(i int, w string) string { return fmt.Sprintf("#%d %s\n", i, w) },
		"| 1 | table":   func(i int, w string) string { return fmt.Sprintf("| %d | %s |\n", i, w) },
	}
	for name, line := range styles {
		if !hasSeedPhrase(written([][]string{en}, "", line)) {
			t.Errorf("English words counted as %q: not found", name)
		}
		if !hasSeedPhrase([]byte(composed(string(written([][]string{ko}, "", line))))) {
			t.Errorf("Korean words counted as %q: not found", name)
		}
	}
	// "word" and "number" are words of the list: a phrase that has one, with
	// its words numbered, is still found.
	for _, w := range []string{"word", "number"} {
		p := phraseWith(rnd, 24, w)
		for _, name := range []string{"1st: on a row", "Word 1:", "#1"} {
			if !hasSeedPhrase(written([][]string{p}, "", styles[name])) {
				t.Errorf("a phrase with %q in it, counted as %q: not found", w, name)
			}
		}
		if !hasSeedPhrase([]byte(numberedRow(p))) {
			t.Errorf("a phrase with %q in it, numbered on one line: not found", w)
		}
	}
}

func numberedRow(p []string) string {
	var b strings.Builder
	for i, w := range p {
		fmt.Fprintf(&b, "%d. %s ", i+1, w)
	}
	return b.String()
}

// fromEntropy returns the English phrase of an entropy given in hex, the way
// the published test vectors are defined.
func fromEntropy(t *testing.T, entropy string) []string {
	t.Helper()
	ent, err := hex.DecodeString(entropy)
	if err != nil {
		t.Fatal(err)
	}
	var bits strings.Builder
	for _, b := range ent {
		fmt.Fprintf(&bits, "%08b", b)
	}
	sum := sha256.Sum256(ent)
	s := bits.String() + fmt.Sprintf("%08b", sum[0])[:len(ent)/4]
	list := seedLists().words[langEnglish]
	words := make([]string, len(s)/11)
	for i := range words {
		v, _ := strconv.ParseInt(s[i*11:i*11+11], 2, 32)
		words[i] = list[v]
	}
	return words
}

// vectorEntropies are the entropies of the published BIP39 test vectors
// (trezor/python-mnemonic vectors.json, English).
func vectorEntropies() []string {
	out := []string{
		"9e885d952ad362caeb4efe34a8e91bd2", "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
		"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "c0ba5a8e914111210f2bd131f3d5e08d",
		"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
		"23db8160a31d3e0dca3688ed941adbf3", "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
		"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "f30f8c1da665478f49b001d94c5fc452",
		"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
	}
	for _, n := range []int{16, 24, 32} {
		for _, b := range []string{"00", "7f", "80", "ff"} {
			out = append(out, strings.Repeat(b, n))
		}
	}
	return out
}

// publicPhrases are the phrases everyone knows, put together here: the
// defaults of development tools from pieces, the test vectors from their
// entropy.
func publicPhrases(t *testing.T) map[string][]string {
	t.Helper()
	list := seedLists().words[langEnglish]
	// By their places in the list, so that the words are not spelled here.
	at := func(places ...int) []string {
		out := make([]string, len(places))
		for i, p := range places {
			out[i] = list[p]
		}
		return out
	}
	out := map[string][]string{
		"Hardhat default": append(strings.Fields(strings.Repeat("test ", 11)), "junk"),
		"Ganache default": at(1172, 1037, 203, 1538, 1263, 1371, 342, 1046, 1321, 1728, 679, 364),
		"Truffle default": at(266, 1084, 258, 1734, 1385, 407, 873, 1482, 1639, 422, 1757, 1854),
	}
	for _, e := range vectorEntropies() {
		out["vector "+e[:8]+"/"+strconv.Itoa(len(e))] = fromEntropy(t, e)
	}
	return out
}

func TestEveryPublicPhraseHashIsOfAPhrase(t *testing.T) {
	pub := publicPhrases(t)
	if len(pub) != len(publicSeedHashes) || len(seedLists().public) != len(publicSeedHashes) {
		t.Errorf("%d phrases put together, %d hashes built in, %d read", len(pub), len(publicSeedHashes), len(seedLists().public))
	}
	for name, p := range pub {
		if !bip39Valid(indexes(p)) {
			t.Errorf("%s: the words put together here do not pass the checksum", name)
		}
		if !publicSeed(indexes(p)) {
			t.Errorf("%s: its hash is not built in", name)
		}
	}
}

func TestPublicPhrasesAreNotReported(t *testing.T) {
	rnd := rand.New(rand.NewSource(5))
	pub := publicPhrases(t)
	// A file like vectors.json: every vector in a string, hex between them.
	var vectors strings.Builder
	vectors.WriteString("{\"english\": [\n")
	for _, e := range vectorEntropies() {
		fmt.Fprintf(&vectors, "  [\"%s\",\n   \"%s\",\n   \"%x\"],\n", e, strings.Join(fromEntropy(t, e), " "), sha256.Sum256([]byte(e)))
	}
	vectors.WriteString("]}\n")
	if got := seedLook([]byte(vectors.String())); got != seedPublicOnly {
		t.Errorf("a file of all test vectors: %d", got)
	}
	// The same vectors in Korean, as the published file has them too.
	korean := seedLists().words[langKorean]
	var both strings.Builder
	for _, e := range vectorEntropies() {
		words := make([]string, 0, 24)
		for _, tok := range indexes(fromEntropy(t, e)) {
			words = append(words, korean[tok.v])
		}
		line := strings.Join(words, " ")
		fmt.Fprintf(&both, "[\"%s\", \"%s\"],\n", e, line)
		for style, body := range map[string]string{"decomposed": line, "composed": composed(line)} {
			if got := seedLook([]byte(body)); got != seedPublicOnly {
				t.Errorf("Korean vector %s, %s: %d", e[:8], style, got)
			}
		}
	}
	if got := seedLook([]byte(vectors.String() + both.String())); got != seedPublicOnly {
		t.Errorf("a file of all test vectors in English and Korean: %d", got)
	}
	for name, p := range pub {
		line := strings.Join(p, " ")
		for style, body := range map[string]string{
			"alone":           line,
			"after a label":   "MNEMONIC=\"" + line + "\"\n",
			"in a sentence":   "Use the seed phrase " + line + " for local test only.\n",
			"a word a line":   string(written([][]string{p}, "", func(i int, w string) string { return fmt.Sprintf("%d. %s\n", i, w) })),
			"in capitals":     strings.ToUpper(line),
			"twice":           line + "\n" + line + "\n",
			"with a stranger": line + "\n\nxyzzy\n\n" + strings.Join(pub["Ganache default"], " "),
		} {
			if got := seedLook([]byte(body)); got != seedPublicOnly {
				t.Errorf("%s, %s: %d", name, style, got)
			}
		}
		// Next to a phrase of one's own the file is reported.
		own := strings.Join(phraseWords(rnd, langEnglish, 12), " ")
		for style, body := range map[string]string{
			"own phrase after":      line + "\n\nmine:\n" + own,
			"own phrase before":     own + "\n--\n" + line,
			"own phrase right next": line + "\n" + own,
		} {
			if got := seedLook([]byte(body)); got != seedFound {
				t.Errorf("%s, %s: %d", name, style, got)
			}
		}
	}
}

// The keyed hash behind the Electrum rule, checked on a text that is no
// phrase against a value worked out with another program (Python's hmac).
func TestSeedVersionMAC(t *testing.T) {
	const want = "d6e78c506dd34ffd05dd028de8c02936be9f6d8c97581fa31c90ce27938ba0cb1708eb6229ec9b1e633b07f19d6fb6b1b117b99463d55f561340f4e484601988"
	if got := hex.EncodeToString(seedVersionMAC([]byte("not a seed, only a test of the keyed hash"))); got != want {
		t.Errorf("HMAC-SHA512 under \"Seed version\" = %s", got)
	}
}
