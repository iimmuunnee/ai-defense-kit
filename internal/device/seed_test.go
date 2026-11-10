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
	"unicode/utf16"
)

// Test phrases are put together while the test runs, from the built-in word
// list and with their checksum worked out here: none is written in this file,
// and none is ever printed. A failure names its case, never the phrase.

// phraseWords returns n words of lang that pass the BIP39 checksum. The
// checksum is worked out on a string of bits, apart from the code under test.
func phraseWords(rnd *rand.Rand, lang, n int) []string {
	list := seedLists().words[lang]
	for {
		ent := make([]byte, n*4/3)
		for i := range ent {
			ent[i] = byte(rnd.Intn(256))
		}
		var bits strings.Builder
		for _, b := range ent {
			fmt.Fprintf(&bits, "%08b", b)
		}
		sum := sha256.Sum256(ent)
		bits.WriteString(fmt.Sprintf("%08b", sum[0])[:n/3])
		s := bits.String()
		words := make([]string, n)
		for i := range words {
			v, _ := strconv.ParseInt(s[i*11:i*11+11], 2, 32)
			words[i] = list[v]
		}
		// Like a real one: no word twice, and not in dictionary order.
		if len(slices.Compact(sorted(slices.Clone(words)))) == n && !slices.IsSorted(words) {
			return words
		}
	}
}

func sorted(s []string) []string { slices.Sort(s); return s }

// electrumWords returns 12 words that fail the BIP39 checksum and pass
// Electrum's.
func electrumWords(rnd *rand.Rand) []string {
	list := seedLists().words[langEnglish]
	for {
		words := make([]string, 12)
		for i := range words {
			words[i] = list[rnd.Intn(len(list))]
		}
		if len(slices.Compact(sorted(slices.Clone(words)))) == 12 && !bip39Valid(indexes(words)) && electrumValid(indexes(words)) {
			return words
		}
	}
}

func indexes(words []string) []seedTok {
	out := make([]seedTok, len(words))
	for i, w := range words {
		out[i] = seedTok{v: uint16(seedLists().index[w])}
	}
	return out
}

// composed turns the word list's decomposed Hangul into syllables, the way a
// text editor saves it.
func composed(s string) string {
	var out []rune
	for _, r := range s {
		n := len(out)
		switch {
		case r >= 0x1161 && r <= 0x1175 && n > 0 && out[n-1] >= 0x1100 && out[n-1] <= 0x1112:
			out[n-1] = 0xAC00 + ((out[n-1]-0x1100)*21+(r-0x1161))*28
		case r >= 0x11A8 && r <= 0x11C2 && n > 0 && out[n-1] >= 0xAC00 && out[n-1] <= 0xD7A3 && (out[n-1]-0xAC00)%28 == 0:
			out[n-1] += r - 0x11A7
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

func utf16LE(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func utf16BE(s string) []byte {
	out := []byte{0xFE, 0xFF}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u>>8), byte(u))
	}
	return out
}

func TestWordListsAreTheOfficialOnes(t *testing.T) {
	l := seedLists()
	for lang, words := range l.words {
		if len(words) != 2048 {
			t.Fatalf("list %d has %d words", lang, len(words))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(l.words[langEnglish], "\n") + "\n"))
	if got := hex.EncodeToString(sum[:]); got != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Errorf("the English list is not the official one: %s", got)
	}
	if !slices.IsSorted(l.words[langEnglish]) {
		t.Error("the English list is not in alphabetical order")
	}
	if len(l.index) != 4096 {
		t.Errorf("index holds %d words", len(l.index))
	}
}

// The published all-zero and all-one vectors, put together here.
func TestChecksumOfPublishedVectors(t *testing.T) {
	rep := func(w string, n int, last string) []seedTok {
		return indexes(append(strings.Fields(strings.Repeat(w+" ", n)), last))
	}
	for _, c := range []struct {
		name string
		toks []seedTok
		want bool
	}{
		{"zero 12", rep("abandon", 11, "about"), true},
		{"zero 24", rep("abandon", 23, "art"), true},
		{"ones 12", rep("zoo", 11, "wrong"), true},
		{"zero 12 wrong last", rep("abandon", 11, "abandon"), false},
	} {
		if got := bip39Valid(c.toks); got != c.want {
			t.Errorf("%s: valid = %v", c.name, got)
		}
	}
}

func TestFindsSeedPhrase(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	numbered := func(w []string, sep string) string {
		var b strings.Builder
		for i, x := range w {
			fmt.Fprintf(&b, "%d. %s%s", i+1, x, sep)
		}
		return b.String()
	}
	cases := map[string][]byte{}
	for _, n := range []int{12, 15, 18, 21, 24} {
		w := phraseWords(rnd, langEnglish, n)
		cases[fmt.Sprintf("%d words on one line", n)] = []byte(strings.Join(w, " "))
		cases[fmt.Sprintf("%d words one per line", n)] = []byte(strings.Join(w, "\n") + "\n")
		cases[fmt.Sprintf("%d words numbered", n)] = []byte(numbered(w, "\r\n"))
		cases[fmt.Sprintf("%d words numbered on one line", n)] = []byte(numbered(w, " "))
		cases[fmt.Sprintf("%d words with commas", n)] = []byte(strings.Join(w, ", "))
		cases[fmt.Sprintf("%d words as a JSON list", n)] = []byte(`{"m": ["` + strings.Join(w, `", "`) + `"]}`)
		cases[fmt.Sprintf("%d words in capitals", n)] = []byte(strings.ToUpper(strings.Join(w, " ")))
		cases[fmt.Sprintf("%d words after a label", n)] = []byte("My wallet seed phrase:\n" + strings.Join(w, " ") + "\nkeep it!\n")
		cases[fmt.Sprintf("%d words in a note", n)] = []byte("오늘 지갑을 만들었다.\n\n" + strings.Join(w, " ") + "\n\n잊지 말 것.\n")
		cases[fmt.Sprintf("%d words UTF-16LE", n)] = utf16LE(strings.Join(w, "\r\n"))
		cases[fmt.Sprintf("%d words UTF-16BE", n)] = utf16BE(strings.Join(w, " "))
		cases[fmt.Sprintf("%d words UTF-8 mark", n)] = append([]byte{0xEF, 0xBB, 0xBF}, strings.Join(w, " ")...)
		k := phraseWords(rnd, langKorean, n)
		cases[fmt.Sprintf("%d Korean words decomposed", n)] = []byte(strings.Join(k, " "))
		cases[fmt.Sprintf("%d Korean words composed", n)] = []byte(composed(strings.Join(k, " ")))
		cases[fmt.Sprintf("%d Korean words composed UTF-16", n)] = utf16LE(composed(strings.Join(k, "\r\n")))
	}
	cases["electrum 12 words"] = []byte(strings.Join(electrumWords(rnd), " "))
	// Several phrases one under another with nothing between them.
	var many []string
	for i := 0; i < 6; i++ {
		many = append(many, strings.Join(phraseWords(rnd, langEnglish, 24), " "))
	}
	cases["six phrases, one per line"] = []byte(strings.Join(many, "\n"))
	for name, body := range cases {
		if !hasSeedPhrase(body) {
			t.Errorf("%s: not found", name)
		}
	}
}

func TestLeavesOtherTextAlone(t *testing.T) {
	rnd := rand.New(rand.NewSource(2))
	l := seedLists()
	en, ko := l.words[langEnglish], l.words[langKorean]
	shuffled := slices.Clone(en)
	rnd.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	reversed := slices.Clone(en)
	slices.Reverse(reversed)
	w := phraseWords(rnd, langEnglish, 12)
	k := phraseWords(rnd, langKorean, 12)

	// One word swapped for another list word so that no checksum holds.
	broken := slices.Clone(w)
	for {
		broken[11] = en[rnd.Intn(len(en))]
		if !bip39Valid(indexes(broken)) && !electrumValid(indexes(broken)) && !slices.Contains(broken[:11], broken[11]) {
			break
		}
	}
	cases := map[string][]byte{
		"the English word list":             []byte(strings.Join(en, "\n") + "\n"),
		"the English word list with CRLF":   []byte(strings.Join(en, "\r\n") + "\r\n"),
		"the English word list on one line": []byte(strings.Join(en, " ")),
		"the English word list, 12 a line":  []byte(wrap(en, 12)),
		"the English word list, 24 a line":  []byte(wrap(en, 24)),
		"the English word list reversed":    []byte(strings.Join(reversed, "\n")),
		"the Korean word list":              []byte(strings.Join(ko, "\n") + "\n"),
		"the Korean word list composed":     []byte(composed(strings.Join(ko, "\n"))),
		"the English word list shuffled":    []byte(strings.Join(shuffled, "\n")),
		"eleven words of a phrase":          []byte(strings.Join(w[:11], " ")),
		"a phrase with a wrong word":        []byte(strings.Join(broken, " ")),
		"a phrase with a stranger inside":   []byte(strings.Join(w[:6], " ") + " zzzz " + strings.Join(w[6:], " ")),
		"a phrase stuck to other letters":   []byte(strings.Join(w, "x ")),
		"half English half Korean":          []byte(strings.Join(w[:6], " ") + " " + strings.Join(k[6:], " ")),
		"published all-zero vector":         []byte(strings.Repeat("abandon ", 11) + "about"),
		"published all-one vector":          []byte(strings.Repeat("zoo ", 11) + "wrong"),
		"a default test phrase":             []byte(strings.Repeat("test ", 11) + "junk"),
		"empty":                             nil,
		"binary":                            {0, 1, 2, 0xff, 0xfe, 0, 0, 7},
		"odd UTF-16":                        {0xFF, 0xFE, 0x61},
	}
	for name, body := range cases {
		if hasSeedPhrase(body) {
			t.Errorf("%s: reported as a seed phrase", name)
		}
	}
}

func wrap(words []string, per int) string {
	var b strings.Builder
	for i, w := range words {
		b.WriteString(w)
		if i%per == per-1 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}
