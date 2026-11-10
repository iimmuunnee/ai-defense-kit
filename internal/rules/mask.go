package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Evidence masking. Evidence must never print a raw secret,
// but it should still show which identifier or address made the rule fire.

// assignLine matches assignment-shaped lines: NAME=value, NAME: value,
// export NAME=value, const NAME = "value", JSON "name": "value".
var assignLine = regexp.MustCompile(`^(\s*(?:(?:export|const|let|var)\s+)*)("[^"]+"|'[^']+'|[A-Za-z_][A-Za-z0-9_.\-]*)(\s*[:=]\s*)(.*)$`)

var (
	quotedValue = regexp.MustCompile(`^("([^"]*)"|'([^']*)')([,;]?)(\s+(?:#|//).*)?$`)
	bareValue   = regexp.MustCompile("^([^\\s\"'`(){}\\[\\]<>,;]+)([,;]?)(\\s+(?:#|//).*)?$")
	envLookup   = regexp.MustCompile(`^(?:process\.env|import\.meta\.env)\.[A-Za-z_][A-Za-z0-9_]*!?$`)
)

// maskable finds the parts of unquoted code that may hold a secret: URLs,
// name=value pairs (any case), and long key-like tokens. Quoted literals are
// handled separately by maskGeneral.
var maskable = regexp.MustCompile(
	"[A-Za-z][A-Za-z0-9+.\\-]*://[^\\s\"'`<>]+" +
		"|[A-Za-z_][A-Za-z0-9_.\\-]*=[^\\s;&,)\\]}=>\"'`][^\\s;&,)\\]}\"'`]*" +
		`|[A-Za-z0-9_\-+/=.]{16,}`)

var moduleSpec = regexp.MustCompile(`^@[a-z0-9][a-z0-9._\-]*/[a-z0-9._\-/]+$`)

var (
	upperSnake   = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	chainSegment = regexp.MustCompile(`^(?:[A-Za-z_$]+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$`)
	pathLike     = regexp.MustCompile(`^(?:/[a-z0-9_.\-{}:\[\]]*)+$`)
	urlParts     = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.\-]*://)([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$`)
	placeholder  = regexp.MustCompile(`^\$\{[^}]*\}$`)
	// mimeType is a media type such as text/javascript or application/ld+json
	// (the value of a type= attribute): shown as it is.
	mimeType  = regexp.MustCompile(`^(?:text|application|image|audio|video|font|model|multipart|message)/[A-Za-z0-9][A-Za-z0-9.+\-]*$`)
	hasDigit  = regexp.MustCompile(`[0-9]`)
	hasLetter = regexp.MustCompile(`[A-Za-z]`)
)

// redact masks a value for rule evidence: values shorter than 8
// characters become exactly ****, longer ones keep finding.Redact's 4-char
// prefix, except private-key and seed-phrase shaped values, which finding.Redact
// shows as **** with no prefix.
func redact(v string) string {
	if v == finding.MarkWords || v == finding.MarkHex {
		return v
	}
	if len([]rune(v)) < 8 {
		return "****"
	}
	return finding.Redact(v)
}

// redactBare masks a bare assignment value. Only whitespace before # or //
// starts a comment, so a value such as abc#def or abc//def is one
// value; it is masked to **** with no prefix, because a dotenv or shell
// reader may treat only the part before # as the secret.
func redactBare(v string) string {
	if strings.Contains(v, "#") || strings.Contains(strings.ReplaceAll(v, "://", ""), "//") {
		return "****"
	}
	return redact(v)
}

// maskEvidence masks a line whose file type is not known (see maskEvidenceFor).
func maskEvidence(line string) string { return maskEvidenceFor("", line) }

// maskEvidenceFor makes the evidence text of a source line in the file rel.
// It fails closed, in this order:
//   - in an env file (see isEnvFile) every value after = is hidden, whatever
//     its shape, and a line without = is hidden whole (a comment line shows
//     only "(주석 생략)");
//   - a comment is never shown: from its marker on, the line is cut and
//     "(주석 생략)" stands in its place. The markers follow the file type and
//     are found without looking at quotes, so a quote in a regex or in the
//     comment itself can't hide a comment;
//   - a quote that doesn't close on what is left hides everything from it on;
//   - the rest goes through the code masks: key and phrase shapes by the text
//     rule first (finding.ScrubKeyMaterial), then names, quoted literals and
//     long tokens; every fragment the masks leave readable is scanned on its
//     own by the value rule (see keep);
//   - key and phrase shapes are looked for once more on the masked line.
//
// Other text inside a closed string, and code outside strings, can still
// appear as the masks leave it.
func maskEvidenceFor(rel, line string) string {
	return finding.ExpandMarks(maskWithMarks(rel, line))
}

func maskWithMarks(rel, line string) string {
	if isEnvFile(rel) {
		return maskEnvLine(line)
	}
	head, cut := cutComment(commentSyntaxFor(rel), line)
	if cut {
		head = strings.TrimRight(head, " \t")
	}
	head, quote := cutOpenQuote(head)
	out := finding.ScrubKeyMaterial(maskCodeLine(head))
	if quote != 0 {
		out += string(quote) + "****"
	}
	if cut {
		if strings.TrimSpace(out) == "" {
			return commentLineMarker
		}
		return out + " " + commentMarker
	}
	return out
}

// maskCodeLine redacts the secret-looking parts of code that has no comment
// and no open string. Private-key and seed-phrase shaped parts go first,
// before any parsing that might give up on an odd line and leave them in; they
// stay marks until maskEvidenceFor writes them as a short Korean note.
func maskCodeLine(line string) string {
	line = finding.ScrubKeyMaterial(line)
	if out, ok := maskAssignment(line); ok {
		return out
	}
	return maskGeneral(line)
}

const commentMarker = "(주석 생략)"

// commentLineMarker is the whole evidence when the line holds only a comment,
// so a reader knows the rule matched inside the comment. (An env file's
// comment line keeps commentMarker; see maskEnvLine.)
const commentLineMarker = "(주석 줄에서 찾음, 내용 생략)"

// envAssign is an env assignment whose name is a valid env name
// ([A-Za-z_][A-Za-z0-9_]*, optionally after export). Any other text before =
// (a dotted or dashed key, the second line of a quoted value) is not a name
// and is never shown.
var envAssign = regexp.MustCompile(`^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*)(.*)$`)

// isEnvFile reports every file the rules' .env* globs can match, and *.env:
// the base name starts or ends with .env (.env, .env.local, .envrc,
// .env-local, .env_local, prod.env).
func isEnvFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	return strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".env")
}

// maskEnvLine keeps only the name of an env assignment. A comment line shows
// the marker, an empty line or an empty value stays, and any other line (the
// second line of a quoted value, a line without =) is hidden whole.
func maskEnvLine(line string) string {
	if m := envAssign.FindStringSubmatch(line); m != nil {
		// A valid name can still be a phrase in UPPER_SNAKE form: scan it too.
		if strings.TrimSpace(m[2]) == "" {
			return finding.ScrubKeyMaterial(line)
		}
		return finding.ScrubValue(m[1]) + "****"
	}
	switch t := strings.TrimSpace(line); {
	case t == "":
		return line
	case strings.HasPrefix(t, "#"):
		return commentMarker
	}
	return "****"
}

// commentSyntax says which comment markers a file type uses.
type commentSyntax struct{ hashAny, hashWS, slash, html, dashes bool }

func commentSyntaxFor(rel string) commentSyntax {
	switch strings.ToLower(path.Ext(rel)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".c", ".h", ".cpp", ".cs", ".rs", ".swift", ".scala", ".dart", ".sol":
		return commentSyntax{slash: true}
	case ".py", ".rb", ".sh", ".bash", ".zsh", ".pl":
		return commentSyntax{hashAny: true}
	case ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties":
		return commentSyntax{hashWS: true}
	case ".php", ".phtml":
		return commentSyntax{hashAny: true, slash: true, html: true}
	case ".html", ".htm", ".xhtml", ".ejs", ".hbs", ".njk", ".erb", ".twig", ".jsp", ".cshtml":
		return commentSyntax{html: true}
	case ".vue", ".svelte":
		return commentSyntax{slash: true, html: true}
	case ".sql", ".lua":
		return commentSyntax{dashes: true}
	case ".json":
		return commentSyntax{}
	}
	// unknown: the first of //, " #", /*, <!--
	return commentSyntax{slash: true, hashWS: true, html: true}
}

// cutComment returns the line before its first comment marker. It doesn't
// look at quotes: a marker inside a string cuts too, so more is hidden, never
// less. "#" counts at the line start or after whitespace, or anywhere when the
// file type allows it; "--" only at the line start or after whitespace; "//"
// unless it ends a URL scheme (see urlScheme).
func cutComment(c commentSyntax, s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		ws := i == 0 || s[i-1] == ' ' || s[i-1] == '\t'
		switch s[i] {
		case '#':
			if c.hashAny || (c.hashWS && ws) {
				return s[:i], true
			}
		case '/':
			if !c.slash || i+1 >= len(s) {
				continue
			}
			if s[i+1] == '*' {
				return s[:i], true
			}
			if s[i+1] == '/' {
				if urlScheme(s, i) {
					i++ // the second slash of ://
					continue
				}
				return s[:i], true
			}
		case '<':
			if c.html && strings.HasPrefix(s[i:], "<!--") {
				return s[:i], true
			}
		case '-':
			if c.dashes && ws && strings.HasPrefix(s[i:], "--") {
				return s[:i], true
			}
		}
	}
	return s, false
}

// urlScheme reports that the // at s[i] ends a URL scheme
// ([A-Za-z][A-Za-z0-9+.-]*://) of two or more characters, as in https:// or
// file:///. "K://", "case 1://" and "=//" are comments.
func urlScheme(s string, i int) bool {
	if i < 3 || s[i-1] != ':' {
		return false
	}
	j := i - 1 // the scheme is s[j:i-1]
	for j > 0 && isSchemeChar(s[j-1]) {
		j--
	}
	return i-1-j >= 2 && isASCIILetter(s[j])
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isSchemeChar(c byte) bool {
	return isASCIILetter(c) || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
}

// cutOpenQuote walks the line once, jumping over closed strings, and returns
// the code before the first quote that doesn't close, and that quote.
func cutOpenQuote(s string) (string, byte) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '"' || c == '\'' || c == '`' {
			j := closingQuote(s, i)
			if j < 0 {
				return s[:i], c
			}
			i = j
		}
	}
	return s, 0
}

// maskAssignment keeps the name and masks the whole value of a simple
// assignment, whatever the value's length.
func maskAssignment(line string) (string, bool) {
	m := assignLine.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	prefix, name, op, val := m[1], m[2], m[3], m[4]
	if val == "" {
		return line, true
	}
	// ==, =>, := and scheme separators (https://) are not assignments.
	if strings.HasPrefix(val, "=") || strings.HasPrefix(val, ">") || strings.HasPrefix(val, "//") {
		return "", false
	}
	head := prefix + keep(name) + op
	// A quoted value that doesn't close on this line may go on over the next
	// ones: hide all of it rather than let the code masks guess.
	if c := val[0]; (c == '"' || c == '\'' || c == '`') && closingQuote(val, 0) < 0 {
		return head + string(c) + "****", true
	}
	if q := quotedValue.FindStringSubmatch(val); q != nil {
		inner, quote := q[2], `"`
		if strings.HasPrefix(q[1], "'") {
			inner, quote = q[3], "'"
		}
		return head + quote + redact(inner) + quote + q[4] + maskGeneral(q[5]), true
	}
	if b := bareValue.FindStringSubmatch(val); b != nil {
		if envLookup.MatchString(b[1]) {
			return head + keep(b[1]) + b[2] + maskGeneral(b[3]), true
		}
		return head + redactBare(b[1]) + b[2] + maskGeneral(b[3]), true
	}
	// .env/YAML style (NAME=my secret): the rest of the line is the value.
	if p := strings.TrimSpace(prefix); (p == "" || p == "export") && !strings.ContainsAny(val, ";&(){}[]<>\"'`") {
		return head + redact(val), true
	}
	return "", false
}

// maskGeneral masks every quoted literal that is not clearly an address,
// path, module name or key, URL credentials and query values, the value of
// every name=value pair, and long opaque tokens, while keeping identifiers
// such as NEXT_PUBLIC_X and process.env.X readable.
func maskGeneral(s string) string {
	var b strings.Builder
	seg := 0
	for i := 0; i < len(s); i++ {
		q := s[i]
		if q != '"' && q != '\'' && q != '`' {
			continue
		}
		j := closingQuote(s, i)
		if j < 0 {
			// Not closed on this line: hide the rest of it (this also keeps the loop linear).
			b.WriteString(maskCode(s[seg:i]))
			b.WriteByte(q)
			b.WriteString("****")
			return b.String()
		}
		b.WriteString(maskCode(s[seg:i]))
		b.WriteByte(q)
		b.WriteString(maskLiteral(s[i+1:j], isKey(s, i, j)))
		b.WriteByte(q)
		seg, i = j+1, j
	}
	b.WriteString(maskCode(s[seg:]))
	return b.String()
}

// maskCode masks unquoted code: URLs, name=value pairs and long tokens.
func maskCode(s string) string {
	return maskable.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, "://") && urlParts.MatchString(m) {
			return maskURL(m)
		}
		if i := strings.IndexByte(m, '='); i > 0 && i < len(m)-1 && m[i+1] != '=' && isName(m[:i]) {
			v := m[i+1:]
			if envLookup.MatchString(v) || isIdentifier(v) {
				return keep(m)
			}
			return keep(m[:i+1]) + redact(v)
		}
		if isIdentifier(m) || isPath(m) {
			return keep(m)
		}
		return redact(m)
	})
}

// keep is how a fragment that the masks leave readable (a name, an
// identifier, a path, a host, a short key) is shown: by itself it is one value,
// so it goes through the value rule (finding.ScrubValue), where words joined
// by any separators, in any case, count. The line as a whole only gets the
// narrower text rule, so identifier-heavy code stays readable.
func keep(s string) string { return finding.ScrubValue(s) }

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

func isName(s string) bool { return nameRe.MatchString(s) }

// closingQuote returns the index of the quote that closes s[i], skipping
// backslash escapes, or -1 when the literal is not closed on this line.
func closingQuote(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case s[i]:
			return j
		}
	}
	return -1
}

// isKey reports a literal used as an object key ({"k": ..., , "k": ...) or
// an index (x["k"], f()["k"], a[0]["k"]). An index needs the [ right before
// the quote and an identifier, ) or ] right before the [, so a
// single-element array such as ["v"] is a value.
func isKey(s string, i, j int) bool {
	if i >= 2 && s[i-1] == '[' && j+1 < len(s) && s[j+1] == ']' {
		if c := s[i-2]; c == ')' || c == ']' || c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return true
		}
	}
	prev, next := byte(0), byte(0)
	if t := strings.TrimRight(s[:i], " \t"); t != "" {
		prev = t[len(t)-1]
	}
	if t := strings.TrimLeft(s[j+1:], " \t"); t != "" {
		next = t[0]
	}
	return next == ':' && (prev == 0 || prev == '{' || prev == ',')
}

// maskLiteral masks the inside of a quoted string, whatever its length,
// unless it is clearly a URL (credentials and query values are masked), a
// path or route, a module name, an UPPER_SNAKE name, or a short key.
func maskLiteral(inner string, key bool) string {
	switch {
	case inner == "":
		return inner
	case strings.ContainsAny(inner, " \t"):
		return redact(inner)
	case key && (len(inner) < 16 || isIdentifier(inner)):
		return keep(inner)
	case upperSnake.MatchString(inner) || moduleSpec.MatchString(inner) || mimeType.MatchString(inner):
		return keep(inner)
	case strings.Contains(inner, "://") && urlParts.MatchString(inner):
		return maskURL(inner)
	case strings.HasPrefix(inner, "/") || strings.HasPrefix(inner, "./") || strings.HasPrefix(inner, "../"):
		return maskPath(inner)
	default:
		return redact(inner)
	}
}

// maskPath keeps a path or route and masks its opaque segments.
func maskPath(p string) string {
	segs := strings.Split(keep(p), "/")
	for i, seg := range segs {
		if opaque(seg) {
			segs[i] = redact(seg)
		}
	}
	return strings.Join(segs, "/")
}

// isIdentifier reports UPPER_SNAKE names and dotted identifier chains
// (process.env.X). Segments with digits or opaque runs do not qualify, so
// JWTs and keys such as AKIA... are still masked.
func isIdentifier(s string) bool {
	if upperSnake.MatchString(s) {
		return true
	}
	segs := strings.Split(s, ".")
	if len(segs) < 2 {
		return false
	}
	for _, seg := range segs {
		if !chainSegment.MatchString(seg) {
			return false
		}
	}
	return true
}

func isPath(s string) bool {
	if !pathLike.MatchString(s) {
		return false
	}
	for _, seg := range strings.Split(s, "/") {
		if opaque(seg) {
			return false
		}
	}
	return true
}

// opaque reports a path segment that looks like a token rather than a word.
func opaque(seg string) bool {
	if strings.ContainsAny(seg, "+=") {
		return true
	}
	return len(seg) >= 16 && hasDigit.MatchString(seg) && hasLetter.MatchString(seg)
}

// maskURL keeps scheme, host and path, and masks credentials, opaque path
// segments, query values (${...} placeholders stay) and the whole fragment.
func maskURL(u string) string {
	p := urlParts.FindStringSubmatch(u)
	if p == nil {
		return redact(u)
	}
	scheme, host, pth, query, frag := p[1], p[2], p[3], p[4], p[5]
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = "****" + host[i:]
	}
	host = keep(host)
	out := scheme + host + maskPath(pth)
	if query != "" {
		out += "?" + maskPairs(query[1:])
	}
	if frag != "" { // fragments can carry tokens (#access_token=...): always masked
		out += "#****"
	}
	return out
}

func maskPairs(q string) string {
	parts := strings.Split(q, "&")
	for i, kv := range parts {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok && kv == "":
		case !ok:
			if opaque(kv) {
				parts[i] = redact(kv)
			} else {
				parts[i] = keep(kv)
			}
		case v == "" || placeholder.MatchString(v):
			parts[i] = keep(k) + "=" + keep(v)
		default:
			parts[i] = keep(k) + "=" + redact(v)
		}
	}
	return strings.Join(parts, "&")
}

// keyName finds the name that made a hide_values rule fire: a variable, a
// property or a call such as PRIVATE_KEY, process.env.X_MNEMONIC or
// new ethers.Wallet.
var keyName = regexp.MustCompile(`(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z0-9_$]*(?:PRIVATE_KEY|PRIV_KEY|MNEMONIC|SEED_PHRASE|privateKey|private_key|mnemonic|Mnemonic|Wallet|fromPhrase)[A-Za-z0-9_$]*`)

// hideEvidence builds the evidence of a hide_values rule. It never masks a
// line: it keeps only the name that matched and the first =, : or ( after it,
// then ****. Anything else on the line, before or after, is dropped, so a
// value cannot survive in a shape the masks don't know. A line without such a
// name gives just ****.
func hideEvidence(line string) string {
	loc := keyName.FindStringIndex(line)
	if loc == nil || loc[1]-loc[0] > 80 {
		return "****"
	}
	// The name itself goes through the key and phrase scan too.
	name, rest := finding.ScrubValueText(line[loc[0]:loc[1]]), line[loc[1]:]
	if i := strings.IndexAny(rest, "=:("); i >= 0 && strings.Trim(rest[:i], " \t\"'`]!?") == "" {
		return name + rest[i:i+1] + "****"
	}
	return name + " ****"
}
