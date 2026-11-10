package report

import (
	"strings"
	"unicode"
)

// SafeText makes repository text safe to show: control and format characters go
// (terminal escapes, bidirectional overrides), and line breaks and tabs become a
// space, so a file name cannot reshape a terminal line or a report. Invalid UTF-8
// becomes U+FFFD. Machine-read fields such as adk-report.json and SARIF URIs keep
// the exact text.
func SafeText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
}

// markdownEscaper stops text outside a code span from forming a link, an HTML tag
// or a code span. The backslash comes first so that it cannot cancel an escape.
var markdownEscaper = strings.NewReplacer(`\`, `\\`, "[", `\[`, "]", `\]`, "<", `\<`, ">", `\>`, "`", "\\`")

// markdownText is repository text for Markdown outside a code span.
func markdownText(s string) string {
	return markdownEscaper.Replace(oneLine(SafeText(s)))
}

// codeSpan is repository text for inside a code span: a backtick would end it.
func codeSpan(s string) string {
	return strings.ReplaceAll(SafeText(s), "`", "'")
}
