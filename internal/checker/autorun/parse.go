package autorun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tidwall/jsonc"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker/secrets"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	maxFindings = 200     // findings per file
	maxMasked   = 1 << 20 // text handed to the masker per file
	maxInJSON   = 120     // characters of a value other than a command, inside the JSON
	maxArgItem  = 300     // characters of one item of args: long ones cannot crowd out the rest
	cutInJSON   = "…(잘림)"
	hidden      = "****"
)

// wholeValueKeys hold what runs or where it connects; their values are not cut.
var wholeValueKeys = map[string]bool{"command": true, "script": true, "headersHelper": true, "url": true}

// firstKeys come first in the JSON, in this order and at any depth, so that decoy
// keys cannot push what runs out of the window. Other keys follow in sorted order.
var firstKeys = []string{"command", "args", "script", "headersHelper", "url", "windows", "linux", "osx"}

// limitFor says how far a value under key k is cut, given the limit around it.
func limitFor(k string, limit int) int {
	switch {
	case k == "args":
		return maxArgItem
	case wholeValueKeys[k]:
		return 0
	}
	return limit
}

// writeJSON writes a value from forDisplay as compact JSON with firstKeys first.
// HTML characters stay as they are: && and < are shell text here.
func writeJSON(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSON(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		rank := func(k string) int {
			if i := slices.Index(firstKeys, k); i >= 0 {
				return i
			}
			return len(firstKeys)
		}
		keys := sortedKeys(x)
		slices.SortStableFunc(keys, func(a, b string) int { return rank(a) - rank(b) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSON(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeJSON(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		buf.Truncate(buf.Len() - 1) // the newline Encode adds
	}
	return nil
}

var errAmbiguousLineBreak = errors.New("주석 끝을 도구마다 다르게 읽을 수 있는 줄바꿈이 있음")

// decodeObject reads a JSON file that may hold comments and trailing commas
// (JSONC) into a top-level object. Nothing in the file is evaluated.
func decodeObject(b []byte) (map[string]any, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if ambiguousLineBreak(string(b)) {
		return nil, errAmbiguousLineBreak
	}
	var v any
	if err := json.Unmarshal(jsonc.ToJSON(b), &v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("최상위 값이 객체가 아님")
	}
	return m, nil
}

// ambiguousLineBreak reports a line break outside a string that readers
// disagree on. The JSONC reader here ends a // comment only at \n, while VS
// Code also ends it at a lone \r, U+2028 and U+2029, so a command could sit
// in what this reader takes for a comment. Such a file is not trusted.
func ambiguousLineBreak(s string) bool {
	const (
		code = iota
		str
		line
		block
	)
	state := code
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if state == str {
			switch r {
			case '\\':
				i++
			case '"':
				state = code
			}
			continue
		}
		switch r {
		case '\u2028', '\u2029':
			return true
		case '\r':
			if i+1 >= len(rs) || rs[i+1] != '\n' {
				return true
			}
		}
		switch state {
		case code:
			switch {
			case r == '"':
				state = str
			case r == '/' && i+1 < len(rs) && rs[i+1] == '/':
				state, i = line, i+1
			case r == '/' && i+1 < len(rs) && rs[i+1] == '*':
				state, i = block, i+1
			}
		case line:
			if r == '\n' {
				state = code
			}
		case block:
			if r == '*' && i+1 < len(rs) && rs[i+1] == '/' {
				state, i = code, i+1
			}
		}
	}
	return false
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// entry is one setting that makes something run. evidence is already cleaned,
// masked and cut, and is all the fingerprint is made from (with an occurrence
// number), so no value the report does not show is in it. raw is the setting as read,
// looked at for key blocks.
type entry struct {
	id       string // finding number, AR-001 ...
	evidence string
	raw      []any
	keyBlock bool // raw holds a private key block
}

// collector gathers the entries of one file and says when to stop: past
// maxFindings entries, past maxMasked of text to mask, or on cancellation.
type collector struct {
	ctx   context.Context
	out   []entry
	spent int
	memo  map[memoKey]maskedText
	err   error
	// fileHasKey says whether the file holds a key block anywhere, so that most
	// files never look through each setting again.
	fileHasKey bool
}

type maskedText struct {
	text string
	cut  bool
}

// memoKey is a masked string and whether it was masked as a command.
type memoKey struct {
	s   string
	cmd bool
}

// isCommandKey reports a key whose value runs: a command, its arguments, a
// helper command. Strings under it are masked as commands (see mask).
func isCommandKey(k string) bool {
	switch strings.ToLower(k) {
	case "command", "args", "headershelper":
		return true
	}
	return false
}

func (c *collector) active() bool {
	if c.err = c.ctx.Err(); c.err != nil {
		return false
	}
	return len(c.out) <= maxFindings && c.spent <= maxMasked
}

// tooMany reports that the file held more than was collected.
func (c *collector) tooMany() bool {
	return len(c.out) > maxFindings || c.spent > maxMasked
}

// add keeps an entry unless the budget ran out while building it: then parts of
// it were not masked and it is dropped.
func (c *collector) add(e entry) {
	if c.spent > maxMasked {
		return
	}
	if c.fileHasKey && holdsKeyBlock(e.raw) {
		e.keyBlock = true
		// Cutting, or a value that is never shown, can leave the notice out.
		if !strings.Contains(e.evidence, secrets.KeyBlockNotice) {
			e.evidence += " " + secrets.KeyBlockNotice
		}
	}
	c.out = append(c.out, e)
}

// holdsKeyBlock looks at text the way the masker gets it, cleaned and collapsed:
// a header broken by a line break or a format character still counts.
func holdsKeyBlock(v any) bool {
	switch x := v.(type) {
	case string:
		return secrets.HasKeyBlock(collapse(clean(x)))
	case []any:
		for _, e := range x {
			if holdsKeyBlock(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if holdsKeyBlock(k) || holdsKeyBlock(e) {
				return true
			}
		}
	}
	return false
}

// mask hides secrets in s, which is shown only through what this returns. Each
// input counts against the budget, even one seen before. Key- and phrase-shaped
// parts go first, on the whole string, before anything can cut it.
//
// A value from the repository that stands alone (a label, an object key, an
// env value, a server or event name) is scanned by the value rule: words
// joined by any separators, mixed or not, any case (finding.ScrubValue). A
// command (cmd: a command or args value, a script body, a helper) is scanned
// by the command rule (finding.ScrubCommand): the text rule over the whole and
// the value rule over each whitespace-separated word, so a command of short
// words joined by && and | stays readable while a phrase written as one word
// is still hidden.
func (c *collector) mask(s string, cmd bool) maskedText {
	if c.spent += len(s); c.spent > maxMasked {
		return maskedText{}
	}
	m, ok := c.memo[memoKey{s, cmd}]
	if !ok {
		scrub := finding.ScrubValueText
		if cmd {
			scrub = finding.ScrubCommandText
		}
		m.text, m.cut = secrets.MaskTextCut(scrub(s))
		if c.memo == nil {
			c.memo = map[memoKey]maskedText{}
		}
		c.memo[memoKey{s, cmd}] = m
	}
	return m
}

// plainText shows a string that stands alone: cleaned, masked and cut.
func (c *collector) plainText(s string, cmd bool) string {
	m := c.mask(collapse(clean(s)), cmd)
	return window(m.text, m.cut)
}

// valueText shows a setting: a string as it is, anything else as compact JSON.
// All of a setting's value is what runs, so nothing in it is cut at maxInJSON.
func (c *collector) valueText(v any) string {
	if s, ok := v.(string); ok {
		return c.plainText(s, true)
	}
	return c.compactJSON(v, false, 0, true)
}

// compactJSON is v as compact JSON. Its strings are masked one at a time before
// marshalling, since quotes turned into \" stop gitleaks' rules from matching. limit
// is how far a string is cut, 0 for not at all.
func (c *collector) compactJSON(v any, hideAll bool, limit int, cmd bool) string {
	var buf bytes.Buffer
	if writeJSON(&buf, c.forDisplay(v, hideAll, limit, cmd)) != nil {
		return ""
	}
	// Each string was scanned on its own, and each array of strings joined (see
	// hideSplitShapes). The JSON as a whole is not scanned: its keys (command,
	// label, type) would join the words of an ordinary command into a run.
	return window(collapse(clean(buf.String())), false)
}

// hideSplitShapes looks at the strings of an array joined, so that a key or a
// phrase given one piece per element (["--key", "<half>", "<half>"],
// ["ZOO_", "QUARTZ_", ...]) is still found. It makes three joins:
//   - with a space and with nothing between the elements, scanned by the text
//     rule (finding.KeyMaterialSpans);
//   - glued: an element that ends in a separator (anything but a letter or a
//     digit) is joined to the next with nothing between, and so is an element
//     that is one separator and one word (_QUARTZ, -곰팡이; see
//     isSeparatorWord) to the one before it; any other pair gets a space. It
//     is scanned by the command rule (finding.CommandKeyMaterialSpans). A
//     phrase cut right after or right before its separators becomes one word
//     again, while the --flags, paths and file names of an ordinary argument
//     list stay apart.
//
// None of them is scanned by the value rule over the whole: the flags of an
// ordinary docker or npm argument list would make a run. Each element alone
// was already scanned (see mask). Every element that takes part in a shape is
// shown as the mark instead of its text; the others stay as they are.
func (c *collector) hideSplitShapes(raw, out []any) {
	var idx []int
	var texts []string
	for i, e := range raw {
		if s, ok := e.(string); ok {
			idx = append(idx, i)
			texts = append(texts, collapse(clean(s)))
		}
	}
	if len(idx) < 2 {
		return
	}
	n := len(texts) - 1
	spaced, tight, glued := make([]string, n), make([]string, n), make([]string, n)
	for k := 0; k < n; k++ {
		spaced[k] = " "
		glued[k] = " "
		if endsInSeparator(texts[k]) || isSeparatorWord(texts[k+1]) {
			glued[k] = ""
		}
	}
	hide := make([]bool, len(idx))
	for _, j := range []struct {
		seps  []string
		spans func(string) [][2]int
	}{
		{spaced, finding.KeyMaterialSpans},
		{tight, finding.KeyMaterialSpans},
		{glued, finding.CommandKeyMaterialSpans},
	} {
		var b strings.Builder
		for k, t := range texts {
			b.WriteString(t)
			if k < n {
				b.WriteString(j.seps[k])
			}
		}
		joined := b.String()
		if c.spent += len(joined); c.spent > maxMasked {
			return
		}
		spans := j.spans(joined)
		if len(spans) == 0 {
			continue
		}
		// spans are sorted and apart (merged), and so are the elements: one pass.
		start, p := 0, 0
		for k, t := range texts {
			end := start + utf8.RuneCountInString(t)
			for p < len(spans) && spans[p][1] <= start {
				p++
			}
			if p < len(spans) && spans[p][0] < end {
				hide[k] = true
			}
			if k < n {
				start = end + utf8.RuneCountInString(j.seps[k])
			}
		}
	}
	for k, h := range hide {
		if !h {
			continue
		}
		mark := finding.MarkWords
		if isHexPiece(texts[k]) {
			mark = finding.MarkHex
		}
		out[idx[k]] = finding.ExpandMarks(mark)
	}
}

// endsInSeparator reports an element whose last character is neither a letter
// nor a digit (zoo_, QUARTZ-, 곰팡이.), so a phrase cut there goes on in the
// next element.
func endsInSeparator(s string) bool {
	r, size := utf8.DecodeLastRuneInString(s)
	return size > 0 && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsMark(r)
}

// isSeparatorWord reports an element that is one separator character followed
// by 2 to 8 letters and nothing else (_QUARTZ, -곰팡이, .vessel), so a phrase
// cut right before its separators goes on from the element before. A --flag
// (the second character is not a letter), a path (/home/dev), a list
// (.ts,.tsx) or a value (-Xmx2g, -c:v) is not one. A one-dash word flag
// (-jar) is, and is glued to the element before; it takes 11 such in a row to
// make a run.
func isSeparatorWord(s string) bool {
	first, size := utf8.DecodeRuneInString(s)
	if size == 0 || unicode.IsLetter(first) || unicode.IsDigit(first) || unicode.IsMark(first) || unicode.IsSpace(first) {
		return false
	}
	letters := 0
	for _, r := range s[size:] {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsMark(r):
		default:
			return false
		}
	}
	return letters >= 2 && letters <= 8
}

// isHexPiece reports a piece made only of hex digits (optionally after 0x).
func isHexPiece(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// jsonString is one string value for the JSON. A value that is not a command is
// cut at limit, so that it cannot use up the window the command needs. before is what
// names the value, its key or the array element ahead of it; masked alone the
// value would lose the name gitleaks' generic rule needs.
func (c *collector) jsonString(s string, limit int, before string, cmd bool) string {
	text := collapse(clean(s))
	m := c.mask(text, cmd)
	if before != "" {
		m.text = c.maskNamed(m.text, before+text+`"`, text)
	}
	r := []rune(m.text)
	switch {
	case limit > 0 && len(r) > limit:
		return string(r[:limit]) + cutInJSON
	case m.cut:
		return m.text + cutInJSON
	}
	return m.text
}

// maskNamed hides in shown what gitleaks finds in named, the value with its name
// beside it. A secret always holds a digit (see secrets.maskable), so a value
// without one is passed over. So is one that may be a path: in python3 -X token
// evil.py the name is an accident and the value is the program that runs.
func (c *collector) maskNamed(shown, named, value string) string {
	if !strings.ContainsAny(value, "0123456789") || strings.ContainsAny(value, `/\.`) {
		return shown
	}
	if c.spent += len(named); c.spent > maxMasked {
		return shown
	}
	for _, secret := range secrets.SecretsIn(named) {
		shown = strings.ReplaceAll(shown, secret, hidden)
	}
	return shown
}

// keyedValue is one value of an object for the JSON.
func (c *collector) keyedValue(k string, v any, hideAll bool, limit int, cmd bool) any {
	if s, ok := v.(string); ok {
		return c.jsonString(s, limit, namePrefix(k), cmd)
	}
	return c.forDisplay(v, hideAll, limit, cmd)
}

// namePrefix is the text put ahead of a value to name it. The generic rule wants
// an assignment, so an argument such as --api-key is written as one as well.
func namePrefix(name string) string { return collapse(clean(name)) + `="` }

// jsonKey is one object key for the JSON. A key nothing was done to stays raw,
// so two keys differing only in invisible characters stay apart; two that end up
// the same after masking or cutting are numbered, so neither value is lost.
func (c *collector) jsonKey(out map[string]any, dups map[string]int, k string) string {
	key := c.jsonString(k, maxInJSON, "", false)
	if key == collapse(clean(k)) && len(k) <= maxInJSON {
		key = k
	}
	name := key
	for _, taken := out[name]; taken; _, taken = out[name] {
		dups[key]++
		name = key + "#" + strconv.Itoa(dups[key]+1)
	}
	return name
}

// forDisplay copies a parsed value for showing. Every string is cleaned first,
// so padding made of line breaks or control characters cannot turn into JSON
// escapes and push the rest out of view. Under an env key, values whose name says
// secret are replaced; with hideAll, every value under env and headers is. limit
// is how far a string is cut, 0 for not at all.
func (c *collector) forDisplay(v any, hideAll bool, limit int, cmd bool) any {
	switch x := v.(type) {
	case string:
		return c.jsonString(x, limit, "", cmd)
	case []any:
		c.spent += len(x)
		out := make([]any, len(x))
		for i, e := range x {
			if c.spent > maxMasked {
				return out
			}
			prev, ok := "", false
			if i > 0 {
				prev, ok = x[i-1].(string)
			}
			if s, isText := e.(string); isText && ok {
				out[i] = c.jsonString(s, limit, namePrefix(prev), cmd)
			} else {
				out[i] = c.forDisplay(e, hideAll, limit, cmd)
			}
		}
		c.hideSplitShapes(x, out)
		return out
	case map[string]any:
		c.spent += len(x)
		out := make(map[string]any, len(x))
		dups := map[string]int{}
		for _, k := range sortedKeys(x) {
			if c.spent > maxMasked {
				return out
			}
			key := c.jsonKey(out, dups, k)
			switch {
			case hideAll && (strings.EqualFold(k, "env") || strings.EqualFold(k, "headers")):
				out[key] = c.hideValues(x[k], false, hideAll)
			case strings.EqualFold(k, "env"):
				out[key] = c.hideValues(x[k], true, hideAll)
			default:
				out[key] = c.keyedValue(k, x[k], hideAll, limitFor(k, limit), cmd || isCommandKey(k))
			}
		}
		return out
	}
	return v
}

// hideValues keeps the names of an env or headers object and replaces its
// values: all of them, or with secretOnly those whose name says secret.
func (c *collector) hideValues(v any, secretOnly, hideAll bool) any {
	m, ok := v.(map[string]any)
	if !ok {
		if secretOnly {
			return c.forDisplay(v, hideAll, maxInJSON, false)
		}
		return hidden
	}
	c.spent += len(m)
	out := make(map[string]any, len(m))
	dups := map[string]int{}
	for _, k := range sortedKeys(m) {
		if c.spent > maxMasked {
			return out
		}
		key := c.jsonKey(out, dups, k)
		if !secretOnly || isSecretName(k) {
			out[key] = hidden
		} else {
			out[key] = c.keyedValue(k, m[k], hideAll, maxInJSON, false)
		}
	}
	return out
}

// secretWords are whole words that mark an environment variable as holding a
// secret; its value is then not shown at all.
var secretWords = map[string]bool{
	"token": true, "password": true, "passwd": true, "pwd": true, "pass": true,
	"secret": true, "key": true, "apikey": true, "auth": true, "credential": true,
}

func isSecretName(name string) bool {
	for _, w := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == '-' }) {
		if secretWords[w] {
			return true
		}
	}
	return false
}

// isEmpty reports a setting that runs nothing: absent, blank, [] or {}.
func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return collapse(clean(x)) == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func isOSBlock(key string) bool { return key == "windows" || key == "linux" || key == "osx" }

// runsByItself reports a runOptions whose runOn is anything but "default". VS
// Code lower-cases the value; "folderOpen" and the newer "worktreeCreated" run
// on their own.
func runsByItself(o map[string]any) bool {
	ro, _ := o["runOptions"].(map[string]any)
	s, ok := ro["runOn"].(string)
	return ok && !strings.EqualFold(strings.TrimSpace(s), "default")
}

// globalKeys are the document-root settings that apply to a task.
var globalKeys = []string{"command", "args", "options", "windows", "linux", "osx"}

// parseTasks reports every object holding such a runOptions, wherever it sits.
// A runOptions directly in an OS block counts for the task around it, so two
// holders in one task give one finding. A task without a label is named by its
// position among the matches.
func (c *collector) parseTasks(root map[string]any) {
	global := map[string]any{}
	for _, k := range globalKeys {
		if v, ok := root[k]; ok {
			global[k] = v
		}
	}
	globalText := ""
	if len(global) > 0 {
		globalText = "; 전역: " + c.compactJSON(global, false, maxInJSON, false)
	}
	task := func(t map[string]any) {
		n := strconv.Itoa(len(c.out) + 1)
		label, _ := t["label"].(string)
		name := c.plainText(label, false)
		if name == "" {
			name = n
		}
		c.add(entry{id: "AR-001", evidence: name + ": " + c.compactJSON(t, false, maxInJSON, false) + globalText, raw: []any{t, global}})
	}
	var walk func(v any, covered bool)
	walk = func(v any, covered bool) {
		if !c.active() {
			return
		}
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e, false)
			}
		case map[string]any:
			if !covered {
				hit := runsByItself(x)
				for _, k := range []string{"windows", "linux", "osx"} {
					sub, _ := x[k].(map[string]any)
					hit = hit || runsByItself(sub)
				}
				if hit {
					task(x)
				}
			}
			for _, k := range sortedKeys(x) {
				walk(x[k], !covered && isOSBlock(k))
			}
		}
	}
	walk(root, false)
}

var devcontainerFields = []string{
	"initializeCommand", "onCreateCommand", "updateContentCommand",
	"postCreateCommand", "postStartCommand", "postAttachCommand",
}

func (c *collector) parseDevcontainer(root map[string]any) {
	for _, f := range devcontainerFields {
		if isEmpty(root[f]) {
			continue
		}
		id := "AR-003"
		if f == "initializeCommand" {
			id = "AR-002"
		}
		c.add(entry{id: id, evidence: f + ": " + c.valueText(root[f]), raw: []any{root[f]}})
	}
}

// parseMCP reports the servers that run something or connect somewhere, under
// mcpServers and under servers, the key VS Code's own format uses. The values under
// env and headers are never shown, and a part the evidence cuts is not in the fingerprint either.
func (c *collector) parseMCP(root map[string]any) {
	for _, group := range []string{"mcpServers", "servers"} {
		servers, _ := root[group].(map[string]any)
		for _, name := range sortedKeys(servers) {
			if !c.active() {
				return
			}
			srv, ok := servers[name].(map[string]any)
			if !ok || isEmpty(srv["command"]) && isEmpty(srv["headersHelper"]) && isEmpty(srv["url"]) {
				continue
			}
			c.add(entry{id: "AR-004", evidence: c.plainText(name, false) + ": " + c.compactJSON(srv, true, maxInJSON, false), raw: []any{name, srv}})
		}
	}
}

// settingsHelpers are the settings Claude Code documents as running your own
// command, in any settings file.
var settingsHelpers = []string{
	"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "fileSuggestion",
	"gcpAuthRefresh", "otelHeadersHelper", "statusLine", "subagentStatusLine",
}

// parseSettings reports the helpers and the hook entries of type "command", named
// by event.
func (c *collector) parseSettings(root map[string]any) {
	for _, f := range settingsHelpers {
		if !isEmpty(root[f]) {
			c.add(entry{id: "AR-004", evidence: f + ": " + c.valueText(root[f]), raw: []any{root[f]}})
		}
	}
	hooks, _ := root["hooks"].(map[string]any)
	for _, event := range sortedKeys(hooks) {
		n := 0
		var walk func(v any)
		walk = func(v any) {
			if !c.active() {
				return
			}
			switch x := v.(type) {
			case []any:
				for _, e := range x {
					walk(e)
				}
			case map[string]any:
				if x["type"] == "command" && !isEmpty(x["command"]) {
					n++
					c.add(entry{id: "AR-004", evidence: c.plainText(event, false) + ": " + c.compactJSON(x, false, maxInJSON, false), raw: []any{event, x}})
				}
				for _, k := range sortedKeys(x) {
					walk(x[k])
				}
			}
		}
		walk(hooks[event])
	}
}

// packageScripts are the scripts npm install and npm ci run, in lifecycle order.
var packageScripts = []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"}

func (c *collector) parsePackage(root map[string]any) {
	scripts, _ := root["scripts"].(map[string]any)
	for _, name := range packageScripts {
		if !isEmpty(scripts[name]) {
			c.add(entry{id: "AR-005", evidence: name + ": " + c.valueText(scripts[name]), raw: []any{scripts[name]}})
		}
	}
}
