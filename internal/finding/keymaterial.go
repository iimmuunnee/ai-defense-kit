package finding

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Key material is anything shaped like a private key or a seed phrase.
// Tokens are the runs of letters and digits; whatever stands between two
// tokens is a separator. URL escapes (%20) and HTML character references
// (&#160;, &nbsp;) count as one separator.
//
// Hex (every rule): 64 or more hex digits, with or without 0x, also when split
// into groups by any separators ("ab12/cd34/...", "0xab12_cd34"). It may also
// be an ordinary digest or a long list of numbers.
//
// Words, text rule (ContainsKeyMaterial, ScrubKeyMaterial: a code line, a
// command, anything shown as it is):
//   - 11 or more words of 2 to 8 Unicode letters, any case, separated by
//     whitespace and/or commas, optionally numbered ("1. zoo", "2) quartz");
//   - 11 or more words of 3 to 8 lowercase ASCII letters where every separator
//     is the same single character or escape (zoo/quartz/..., zoo_quartz_...,
//     zoo%20quartz%20...).
//
// UPPER_SNAKE, camelCase, mixed separators and dotted identifiers are not word
// runs by the text rule, so identifier-heavy code stays readable.
//
// Words, value rule (ValueHasKeyMaterial, ScrubValue: one value or name, such
// as a literal, a job name, a table name): 11 or more words of 2 to 8 Unicode
// letters, any case, joined by any separators, mixed or not.
//
// Words, command rule (ScrubCommand: a command or an argument shown on its
// own): the text rule over the whole, plus the value rule over each
// whitespace-separated word alone.
//
// Reports never show a prefix of it. Each scan is a single pass, so a long
// line costs no more than its length.

const (
	// MarkWords and MarkHex stand for hidden key material until ExpandMarks
	// turns them into text. They are private-use characters, so no masking
	// step treats them as part of a word or a token.
	MarkWords = ""
	MarkHex   = ""

	minSeedWords = 11
	minKeyDigits = 64
)

// hexKey finds 64 hex digits inside a longer token, such as key_<hex> or g<hex>.
var hexKey = regexp.MustCompile(`(?:0[xX])?[0-9a-fA-F]{64,}`)

func isTokenChar(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.IsMark(c) }

// token is a run of letters and digits, as a rune span.
type token struct{ start, end int }

// tokens splits r into tokens. URL escapes (%20) and HTML character
// references (&#160;, &#xA0;, &nbsp;) count as separators, so a phrase joined
// by them is still one run.
func tokens(r []rune) []token {
	var out []token
	for i := 0; i < len(r); {
		if !isTokenChar(r[i]) {
			i += escapeLen(r, i)
			continue
		}
		j := i
		for j < len(r) && isTokenChar(r[j]) {
			j++
		}
		out = append(out, token{i, j})
		i = j
	}
	return out
}

const maxEntity = 32 // longest &name; or &#...; looked at

func isHexDigit(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// escapeLen returns how many runes from r[i] (a separator) to skip: a whole
// %XX, &#digits;, &#xhex; or &letters; escape, or else 1.
func escapeLen(r []rune, i int) int {
	n := len(r)
	switch r[i] {
	case '%':
		if i+2 < n && isHexDigit(r[i+1]) && isHexDigit(r[i+2]) {
			return 3
		}
	case '&':
		j := i + 1
		ok := func(c rune) bool { return c >= 'a' && c <= 'z' }
		if j < n && r[j] == '#' {
			j++
			ok = func(c rune) bool { return c >= '0' && c <= '9' }
			if j < n && (r[j] == 'x' || r[j] == 'X') {
				j++
				ok = isHexDigit
			}
		}
		k := j
		for k < n && k-i < maxEntity && ok(r[k]) {
			k++
		}
		if k > j && k < n && r[k] == ';' {
			return k + 1 - i
		}
	}
	return 1
}

// wordKind tells how a token counts toward a word run: 1 a word (2 to 8
// letters), 0 a number of 1 or 2 digits (list numbering: neither counts nor
// breaks the run), -1 anything else (breaks the run).
func wordKind(t []rune) int {
	digits := 0
	for _, c := range t {
		if unicode.IsDigit(c) {
			digits++
		}
	}
	letters := len(t) - digits
	switch {
	case digits == 0 && letters >= 2 && letters <= 8:
		return 1
	case letters == 0 && digits <= 2:
		return 0
	}
	return -1
}

// hexDigits returns how many hex digits the token holds when it is all hex
// (an optional 0x prefix is not counted), or -1.
func hexDigits(t []rune) int {
	if len(t) > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X') {
		t = t[2:]
	}
	for _, c := range t {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return -1
		}
	}
	return len(t)
}

// runs returns the [start, end) rune spans of every run of tokens that score
// counts as a run (score < 0 breaks a run, the rest add up) whose total
// reaches min. A span starts at the first scoring token and ends at the last
// one.
func runs(r []rune, toks []token, score func([]rune) int, min int) [][2]int {
	var spans [][2]int
	total, first, last := 0, -1, -1
	flush := func() {
		if total >= min {
			spans = append(spans, [2]int{toks[first].start, toks[last].end})
		}
		total, first, last = 0, -1, -1
	}
	for i, t := range toks {
		n := score(r[t.start:t.end])
		if n < 0 {
			flush()
			continue
		}
		if n > 0 {
			if first < 0 {
				first = i
			}
			last = i
			total += n
		}
	}
	flush()
	return spans
}

// valueWordSpans is the word-run rule for a single value or name: tokens
// joined by any separators, mixed or not (see wordKind).
func valueWordSpans(r []rune) [][2]int { return runs(r, tokens(r), wordKind, minSeedWords) }

func hexSpans(r []rune) [][2]int { return runs(r, tokens(r), hexDigits, minKeyDigits) }

// isSpacedSep reports a separator made of whitespace and commas only.
func isSpacedSepText(s []rune) bool {
	for _, c := range s {
		if !isSpacedSep(c) {
			return false
		}
	}
	return len(s) > 0
}

// isNumbering reports a separator after a list number: optional . or ), then
// whitespace or commas ("1. zoo", "2)quartz", "3 lemur").
func isNumbering(s []rune) bool {
	if len(s) > 0 && (s[0] == '.' || s[0] == ')') {
		s = s[1:]
	}
	return len(s) == 0 || isSpacedSepText(s)
}

// spacedRuns finds runs of 11 or more words (2 to 8 Unicode letters, any case)
// separated by whitespace and/or commas. A list number of 1 or 2 digits, with
// an optional . or ) after it, neither counts nor breaks the run.
func spacedRuns(r []rune, toks []token) [][2]int {
	var spans [][2]int
	count, first, last := 0, -1, -1
	flush := func() {
		if count >= minSeedWords {
			spans = append(spans, [2]int{toks[first].start, toks[last].end})
		}
		count, first, last = 0, -1, -1
	}
	prevNum := false // the token before this one was a list number
	for i, t := range toks {
		kind := wordKind(r[t.start:t.end])
		if i > 0 && first >= 0 {
			sep := r[toks[i-1].end:t.start]
			ok := isSpacedSepText(sep) || (prevNum && isNumbering(sep))
			if !ok {
				flush()
			}
		}
		switch kind {
		case 1:
			if first < 0 {
				first = i
			}
			last = i
			count++
		case 0: // a list number: it starts or keeps a run, but doesn't count
			if first < 0 {
				first = i
			}
		default:
			flush()
		}
		prevNum = kind == 0
	}
	flush()
	return spans
}

// isLowerWord reports a token of 3 to 8 lowercase ASCII letters (BIP-39
// English words are lowercase, 3 to 8 letters).
func isLowerWord(t []rune) bool {
	if len(t) < 3 || len(t) > 8 {
		return false
	}
	for _, c := range t {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// isOneSeparator reports a separator that is one character, or one escape
// (%xx, &#...;, &name;).
func isOneSeparator(s []rune) bool {
	return len(s) == 1 || (len(s) > 1 && escapeLen(s, 0) == len(s))
}

// sameSepRuns finds runs of 11 or more lowercase words (see isLowerWord) where
// every separator is the same single character or escape: zoo/quartz/...,
// zoo-quartz-..., zoo%20quartz%20... A run ends where the separator changes,
// so mixed separators never make one run.
func sameSepRuns(r []rune, toks []token) [][2]int {
	var spans [][2]int
	first := -1
	var sep []rune
	flush := func(last int) {
		if first >= 0 && last-first+1 >= minSeedWords {
			spans = append(spans, [2]int{toks[first].start, toks[last].end})
		}
		first = -1
	}
	for i := 0; i+1 < len(toks); i++ {
		a, b := toks[i], toks[i+1]
		s := r[a.end:b.start]
		if !isLowerWord(r[a.start:a.end]) || !isLowerWord(r[b.start:b.end]) || !isOneSeparator(s) {
			flush(i)
			continue
		}
		if first >= 0 && string(s) == string(sep) {
			continue
		}
		flush(i)
		first, sep = i, s
	}
	flush(len(toks) - 1)
	return spans
}

// textWordSpans is the word-run rule for text that is shown as it is (a code
// line, a command): spacedRuns and sameSepRuns, merged.
func textWordSpans(r []rune) [][2]int {
	toks := tokens(r)
	return mergeSpans(append(spacedRuns(r, toks), sameSepRuns(r, toks)...))
}

func mergeSpans(spans [][2]int) [][2]int {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	out := spans[:1]
	for _, sp := range spans[1:] {
		if l := &out[len(out)-1]; sp[0] <= l[1] {
			if sp[1] > l[1] {
				l[1] = sp[1]
			}
			continue
		}
		out = append(out, sp)
	}
	return out
}

// ContainsKeyMaterial reports whether the text s holds something shaped like
// a private key or a seed phrase, by the text rule (see the top of the file).
func ContainsKeyMaterial(s string) bool {
	if hexKey.MatchString(s) {
		return true
	}
	r := []rune(s)
	return len(hexSpans(r)) > 0 || len(textWordSpans(r)) > 0
}

// ScrubKeyMaterial replaces every key-shaped part of the text s with MarkHex
// or MarkWords, by the text rule. ExpandMarks turns the marks into text once
// masking is done.
func ScrubKeyMaterial(s string) string { return scrub(s, textWordSpans) }

// ValueHasKeyMaterial reports whether a single value or name holds something
// shaped like a private key or a seed phrase, by the value rule: words joined
// by any separators, mixed or not, any case.
func ValueHasKeyMaterial(s string) bool {
	if hexKey.MatchString(s) {
		return true
	}
	r := []rune(s)
	return len(hexSpans(r)) > 0 || len(valueWordSpans(r)) > 0
}

// ScrubValue is ScrubKeyMaterial by the value rule (see ValueHasKeyMaterial),
// for a fragment taken from the repository and shown inside a sentence: a job
// name, an action reference, a table or host name, a literal.
func ScrubValue(s string) string { return scrub(s, valueWordSpans) }

// ScrubValueText is ScrubValue with the marks written out.
func ScrubValueText(s string) string { return ExpandMarks(ScrubValue(s)) }

// ScrubNarrow hides only the narrow shapes: 64 or more hex digits (also split
// into groups), and 11 or more words separated by whitespace and/or commas.
// It is the last net over text the tool composed itself (titles, sentences
// with repository fragments already scrubbed), so separators inside a
// composed sentence are never counted.
func ScrubNarrow(s string) string {
	return ExpandMarks(scrub(s, func(r []rune) [][2]int { return spacedRuns(r, tokens(r)) }))
}

// KeyMaterialSpans returns the [start, end) rune spans of everything the text
// rule (ScrubKeyMaterial) would hide in s, so a caller that shows s in parts
// can tell which parts take part in a shape.
func KeyMaterialSpans(s string) [][2]int { return keySpans(s, textWordSpans) }

// CommandKeyMaterialSpans is KeyMaterialSpans by the command rule
// (ScrubCommand): the text rule over the whole, plus the value rule over each
// whitespace-separated word. The spans are sorted and do not overlap.
func CommandKeyMaterialSpans(s string) [][2]int { return keySpans(s, commandWordSpans) }

func keySpans(s string, words func([]rune) [][2]int) [][2]int {
	r := []rune(s)
	var spans [][2]int
	for _, loc := range hexKey.FindAllStringIndex(s, -1) {
		spans = append(spans, [2]int{utf8.RuneCountInString(s[:loc[0]]), utf8.RuneCountInString(s[:loc[1]])})
	}
	spans = append(spans, hexSpans(r)...)
	return mergeSpans(append(spans, words(r)...))
}

// commandWordSpans is the word-run rule for a command: the text rule over the
// whole, and the value rule over each whitespace-separated word alone. A
// phrase written as one word (ZOO_QUARTZ_..., zoo-quartz_vessel...) is found,
// while a command of short words joined by &&, | and flags is not taken for a
// run. Each rune is looked at a bounded number of times.
func commandWordSpans(r []rune) [][2]int {
	spans := textWordSpans(r)
	for i := 0; i < len(r); {
		if unicode.IsSpace(r[i]) {
			i++
			continue
		}
		j := i
		for j < len(r) && !unicode.IsSpace(r[j]) {
			j++
		}
		for _, sp := range valueWordSpans(r[i:j]) {
			spans = append(spans, [2]int{sp[0] + i, sp[1] + i})
		}
		i = j
	}
	return mergeSpans(spans)
}

// ScrubCommand is ScrubKeyMaterial for a command (a task's command or an
// argument, a script body): the text rule over the whole, plus the value rule
// over each whitespace-separated word (see commandWordSpans).
func ScrubCommand(s string) string { return scrub(s, commandWordSpans) }

// ScrubCommandText is ScrubCommand with the marks written out.
func ScrubCommandText(s string) string { return ExpandMarks(ScrubCommand(s)) }

func scrub(s string, words func([]rune) [][2]int) string {
	s = hexKey.ReplaceAllString(s, MarkHex)
	r := []rune(s)
	r = replaceSpans(r, hexSpans(r), MarkHex)
	return string(replaceSpans(r, words(r), MarkWords))
}

func replaceSpans(r []rune, spans [][2]int, mark string) []rune {
	if len(spans) == 0 {
		return r
	}
	out := make([]rune, 0, len(r))
	prev := 0
	for _, sp := range spans {
		out = append(out, r[prev:sp[0]]...)
		out = append(out, []rune(mark)...)
		prev = sp[1]
	}
	return append(out, r[prev:]...)
}

// ExpandMarks writes what a mark stands for, so a reader doesn't take a hidden
// word list or digest for a secret that was removed.
func ExpandMarks(s string) string {
	if !strings.ContainsAny(s, MarkWords+MarkHex) {
		return s
	}
	return strings.NewReplacer(MarkWords, "(긴 단어 나열을 가림)", MarkHex, "(64자리 이상 16진수를 가림)").Replace(s)
}

// Redact keeps the first 4 characters and masks the rest. Values of 4
// characters or fewer are fully masked. A value that holds key material (see
// ValueHasKeyMaterial) shows no prefix at all.
func Redact(secret string) string {
	if ValueHasKeyMaterial(secret) {
		return "****"
	}
	return RedactPrefix(secret)
}

// RedactPrefix keeps the first 4 characters whatever the value is. Fingerprints
// of secrets that are not key material use it so they stay as they were.
func RedactPrefix(secret string) string {
	r := []rune(secret)
	if len(r) <= 4 {
		return "****"
	}
	return string(r[:4]) + "****"
}

func isSpacedSep(c rune) bool { return c == ',' || unicode.IsSpace(c) }

func isSpacedWordChar(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' }

// spacedWordToken returns where the word token starting at r[s] ends, or -1:
// an optional 1 or 2 digit number with . or ), then 2 to 8 letters that are
// not followed by a digit or underscore.
func spacedWordToken(r []rune, s int) int {
	n, j := len(r), s
	k := j
	for k < n && k-j < 2 && r[k] >= '0' && r[k] <= '9' {
		k++
	}
	if k > j && k < n && (r[k] == '.' || r[k] == ')') {
		j = k + 1
		for j < n && (r[j] == ' ' || r[j] == '\t' || r[j] == 0xA0) {
			j++
		}
	} else {
		j = s
	}
	l := j
	for l < n && unicode.IsLetter(r[l]) {
		l++
	}
	if l-j < 2 || l-j > 8 || (l < n && (unicode.IsDigit(r[l]) || r[l] == '_')) {
		return -1
	}
	return l
}

// spacedWordRuns returns the [start, end) rune spans of every run of at least
// minSeedWords spacedWordToken tokens.
func spacedWordRuns(r []rune) [][2]int {
	var spans [][2]int
	n := len(r)
	start, last, count := 0, 0, 0
	flush := func() {
		if count >= minSeedWords {
			spans = append(spans, [2]int{start, last})
		}
		count = 0
	}
	for i := 0; i < n; {
		s := i
		for s < n && isSpacedSep(r[s]) {
			s++
		}
		if s >= n {
			break
		}
		if end := spacedWordToken(r, s); end >= 0 && (count == 0 || s > i) {
			if count == 0 {
				start = s
			}
			count++
			last, i = end, end
			continue
		}
		flush()
		i = s
		if isSpacedWordChar(r[i]) {
			for i < n && isSpacedWordChar(r[i]) {
				i++
			}
		} else {
			i++
		}
	}
	flush()
	return spans
}

// ScrubText hides every key- or phrase-shaped part of a text that is shown as
// it is, and writes the short Korean note in its place.
func ScrubText(s string) string { return ExpandMarks(ScrubKeyMaterial(s)) }
