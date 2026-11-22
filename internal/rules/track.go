package rules

import (
	"regexp"
	"strings"
)

// tracker follows, within one function of one file, the variables a line rule
// with input_var_regex should read as user input. It is a line-by-line guess,
// not a parser:
//
//   - A line "$name = value;" or "$name .= value;" whose value, once the rule's
//     masks and numberMasks are applied, matches an input_var_regex makes $name
//     hold the first matched text.
//   - "$name = value;" whose value still holds $name keeps it (the same value
//     changed in place, such as a replace or trim). Any other "=" lets it go.
//   - A value built from another tracked variable is not followed, so
//     "$b = 'x' . $a;" does not make $b input.
//   - A named function declaration starts over.
//
// Comment lines (skip_line_regex) change nothing.
type tracker struct {
	vars  map[string]string // "$name" -> the input text it holds
	names map[string]*regexp.Regexp
}

var (
	assignRe   = regexp.MustCompile(`^\s*(\$[A-Za-z_]\w*)\s*(\.?=)([^=>].*)$`)
	funcDeclRe = regexp.MustCompile(`\bfunction\s+&?\s*[A-Za-z_]\w*\s*\(`)
	// numberMasks: a value only checked, counted, hashed or turned into a number
	// is not carried as input, whatever the rule's own masks are.
	numberMasks = []*regexp.Regexp{
		regexp.MustCompile(`\b(?i:intval|floatval|boolval|isset|empty|is_numeric|is_int|ctype_digit|count|strlen|md5|sha1|crc32|hash)\s*\([^()]*\)`),
		regexp.MustCompile(`\(\s*(?i:int|integer|float|double|bool|boolean)\s*\)\s*\$\w+(?:\s*\[[^\]]*\])*`),
	}
)

// newTracker returns nil when r tracks nothing or the file holds no input it
// tracks; a nil tracker is inactive and its update does nothing.
func newTracker(r Rule, content string) *tracker {
	if len(r.inputRe) == 0 || !matchesAny(content, r.inputRe) {
		return nil
	}
	return &tracker{vars: map[string]string{}, names: map[string]*regexp.Regexp{}}
}

func (t *tracker) active() bool { return t != nil && len(t.vars) > 0 }

// substitute puts each tracked variable back as the input text it holds.
func (t *tracker) substitute(l string) string {
	for name, src := range t.vars {
		l = t.nameRe(name).ReplaceAllLiteralString(l, src)
	}
	return l
}

func (t *tracker) update(r Rule, l string) {
	if t == nil || matchesAny(l, r.skipRe) {
		return
	}
	if funcDeclRe.MatchString(l) {
		clear(t.vars)
		return
	}
	m := assignRe.FindStringSubmatch(l)
	if m == nil || m[1] == "$this" {
		return
	}
	name, op := m[1], m[2]
	value := applyMasks(numberMasks, applyMasks(r.maskRe, m[3]))
	for _, re := range r.inputRe {
		if src := re.FindString(value); src != "" {
			t.vars[name] = strings.TrimSpace(src)
			return
		}
	}
	if op == ".=" {
		return
	}
	if _, held := t.vars[name]; held && t.nameRe(name).MatchString(value) {
		return
	}
	delete(t.vars, name)
}

func (t *tracker) nameRe(name string) *regexp.Regexp {
	re := t.names[name]
	if re == nil {
		re = regexp.MustCompile(regexp.QuoteMeta(name) + `\b`)
		t.names[name] = re
	}
	return re
}
