package device

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// fillerWords are everyday words that are not in the English list (checked
// when the test starts).
var fillerWords = strings.Fields(`the of and to in is was that it for with as on be at by this had not are but
	from or have an they which one you were her all she there would their we him been has when who will more no
	if out so said what its into than them only some could these two may then do first any my now such like our
	over man me even most made after also did many before must through years where much your way well down should
	because each just those people how too little state good very make world still own see men work long get here
	between both life being under never day same another know while last might us great old year off come since
	against go came right used take three himself few house use during without again place around however home
	small found thought went say part once general high upon school every does got united left number course war
	until always away something fact though water less public put think almost hand enough far took head yet
	government system better set told nothing night end why called eyes find going look asked later knew`)

// codeWords are what source code is mostly made of besides names.
var codeWords = strings.Fields(`func return if else for range var const import package struct interface map
	string int bool nil true false err def class self None print len append fmt http json ctx req res cfg tmp`)

// textMaker writes ordinary files in memory. share is how many of the words
// are words of the seed list.
type textMaker struct {
	rnd    *rand.Rand
	list   []string
	filler []string
}

func (m textMaker) word(share float64) string {
	if m.rnd.Float64() < share {
		return m.list[m.rnd.Intn(len(m.list))]
	}
	return m.filler[m.rnd.Intn(len(m.filler))]
}

// prose is sentences of 6 to 20 words.
func (m textMaker) prose(words int, share float64) []byte {
	var b strings.Builder
	for n := 0; n < words; {
		k := 6 + m.rnd.Intn(15)
		for i := 0; i < k; i++ {
			w := m.word(share)
			if i == 0 {
				w = strings.ToUpper(w[:1]) + w[1:]
			}
			b.WriteString(w)
			if i < k-1 {
				b.WriteString([]string{" ", " ", " ", ", "}[m.rnd.Intn(4)])
			}
		}
		b.WriteString([]string{". ", ".\n", "? ", ".\n\n"}[m.rnd.Intn(4)])
		n += k
	}
	return []byte(b.String())
}

// wordPerLine is a vocabulary list: one word on each line.
func (m textMaker) wordPerLine(words int, share float64) []byte {
	var b strings.Builder
	for i := 0; i < words; i++ {
		b.WriteString(m.word(share) + "\n")
	}
	return []byte(b.String())
}

// counted is a vocabulary list with every word counted, as line(i, word)
// writes it.
func (m textMaker) counted(words int, share float64, line string) []byte {
	var b strings.Builder
	for i := 0; i < words; i++ {
		fmt.Fprintf(&b, line, i+1, m.word(share))
	}
	return []byte(b.String())
}

// code is lines of source with list words as names.
func (m textMaker) code(lines int, share float64) []byte {
	var b strings.Builder
	kw := func() string { return codeWords[m.rnd.Intn(len(codeWords))] }
	for i := 0; i < lines; i++ {
		switch m.rnd.Intn(4) {
		case 0:
			fmt.Fprintf(&b, "%s %s(%s %s, %s %s) %s {\n", kw(), m.word(share), m.word(share), kw(), m.word(share), kw(), kw())
		case 1:
			fmt.Fprintf(&b, "\t%s := %s.%s(%s, %s)\n", m.word(share), m.word(share), m.word(share), m.word(share), m.word(share))
		case 2:
			fmt.Fprintf(&b, "\t%s %s != %s { %s %s }\n", kw(), m.word(share), kw(), kw(), m.word(share))
		default:
			fmt.Fprintf(&b, "\t// %s\n", m.prose(8, share))
		}
	}
	return []byte(b.String())
}

// korean is Korean sentences: list words mostly carry a particle, as written
// Korean does, and so are not list words any more.
func (m textMaker) korean(words int, bare float64) []byte {
	ko := seedLists().words[langKorean]
	particles := []string{"이", "가", "을", "를", "은", "는", "에", "의", "도", "으로"}
	var b strings.Builder
	for i := 0; i < words; i++ {
		w := composed(ko[m.rnd.Intn(len(ko))])
		if m.rnd.Float64() >= bare {
			w += particles[m.rnd.Intn(len(particles))]
		}
		b.WriteString(w)
		if i%12 == 11 {
			b.WriteString(".\n")
		} else {
			b.WriteByte(' ')
		}
	}
	return []byte(b.String())
}

// onlyListWords is the worst case: nothing but random words of the list,
// perLine on a line, with a line of other words between the lines.
func (m textMaker) onlyListWords(lines, perLine int) []byte {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		for j := 0; j < perLine; j++ {
			b.WriteString(m.word(1) + " ")
		}
		b.WriteString("\n-- " + m.word(0) + " --\n")
	}
	return []byte(b.String())
}

// TestSeedFalseAlarmCount counts how many ordinary files, made while the test
// runs, are reported. The numbers are logged (go test -v) and written into
// the documentation; the limits below keep them from getting worse unseen.
func TestSeedFalseAlarmCount(t *testing.T) {
	l := seedLists()
	var filler []string
	for _, w := range fillerWords {
		if _, in := l.index[w]; !in {
			filler = append(filler, w)
		}
	}
	m := textMaker{rnd: rand.New(rand.NewSource(20261110)), list: l.words[langEnglish], filler: filler}
	const files = 300
	for _, c := range []struct {
		name string
		make func() []byte
		// most is the largest count accepted; -1 only logs.
		most int
	}{
		{"English prose, 1 word in 4 from the list, 400 words", func() []byte { return m.prose(400, 0.25) }, 0},
		{"English prose, 1 word in 2 from the list, 400 words", func() []byte { return m.prose(400, 0.5) }, 9},
		{"vocabulary list, 1 word in 2 from the list, 500 lines", func() []byte { return m.wordPerLine(500, 0.5) }, 9},
		{"numbered vocabulary list (1. x), 1 word in 2 from the list, 500 lines", func() []byte { return m.counted(500, 0.5, "%d. %s\n") }, 9},
		{"counted vocabulary list (Word 1: x), 1 word in 2 from the list, 500 lines", func() []byte { return m.counted(500, 0.5, "Word %d: %s\n") }, 9},
		{"vocabulary list, 3 words in 4 from the list, 500 lines", func() []byte { return m.wordPerLine(500, 0.75) }, -1},
		{"source code, 1 name in 4 from the list, 200 lines", func() []byte { return m.code(200, 0.25) }, 0},
		{"source code, 1 name in 2 from the list, 200 lines", func() []byte { return m.code(200, 0.5) }, 9},
		{"Korean prose, 1 list word in 3 without a particle, 400 words", func() []byte { return m.korean(400, 0.33) }, 0},
		{"exactly 12 random list words on a line, 1 line", func() []byte { return m.onlyListWords(1, 12) }, -1},
		{"30 random list words on a line, 20 lines", func() []byte { return m.onlyListWords(20, 30) }, -1},
	} {
		hits := 0
		for i := 0; i < files; i++ {
			if hasSeedPhrase(c.make()) {
				hits++
			}
		}
		t.Logf("%s: %d of %d files reported", c.name, hits, files)
		if c.most >= 0 && hits > c.most {
			t.Errorf("%s: %d of %d files reported, at most %d expected", c.name, hits, files, c.most)
		}
	}
}
