// Package supabase checks Supabase SQL migrations for public tables that
// never get row level security (SB-001).
package supabase

import (
	"regexp"
	"sort"
	"strings"
)

const (
	ident = `"(?:[^"]|"")+"|[\p{L}_][\p{L}\p{N}_$]*`
	// qualified is an optional schema followed by a table name; both are captured.
	qualified = `(` + ident + `)(?:\s*\.\s*(` + ident + `))?`
)

// warnEventTrigger names the migration that installs the auto-enable trigger.
func warnEventTrigger(path string) string {
	return "RLS 자동 활성화 트리거가 있어 모든 테이블의 RLS 점검을 건너뛰었습니다 (" + path + ")."
}

// warnDynamicEnable names the migration whose do block enables RLS with dynamic SQL.
func warnDynamicEnable(path string) string {
	return "do 블록 안에서 동적 SQL로 RLS를 켜는 코드가 있어 모든 테이블의 RLS 점검을 건너뛰었습니다 (" + path + ")."
}

var (
	createRe = regexp.MustCompile(`(?i)\bcreate\s+((?:(?:global|local)\s+)?(?:temp|temporary)\s+)?(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?` + qualified)
	alterRe  = regexp.MustCompile(`(?i)\balter\s+table\s+(?:(?:only|if\s+exists)\s+)*` + qualified + `\s+([^;]*)`)
	rlsRe    = regexp.MustCompile(`(?i)\b(enable|disable)\s+row\s+level\s+security\b`)
	renameRe = regexp.MustCompile(`(?i)^rename\s+to\s+(` + ident + `)`)
	schemaRe = regexp.MustCompile(`(?i)^set\s+schema\s+(` + ident + `)`)
	doRe     = regexp.MustCompile(`(?i)^\s*do(\s+language\s+\S+)?\s*$`)
	dropRe   = regexp.MustCompile(`(?i)\bdrop\s+table\s+(?:if\s+exists\s+)?([^;]*)`)
	nameRe   = regexp.MustCompile(`^\s*` + qualified)

	eventTriggerRe = regexp.MustCompile(`(?i)\bcreate\s+event\s+trigger\b`)
	enableRLSRe    = regexp.MustCompile(`(?i)\benable\s+row\s+level\s+security\b`)
	doStartRe      = regexp.MustCompile(`(?i)\bdo\s+(?:language\s+\S+\s+)?(\$[\p{L}_]*\$)`)
	executeRe      = regexp.MustCompile(`(?i)\bexecute\b`)
)

// SQLFile is one migration. Path is only echoed back in Table.File.
type SQLFile struct {
	Path    string
	Content string
}

// Table is a public table that has no row level security.
type Table struct {
	Name string // as written, without quotes
	File string
	Line int
}

// FindTablesWithoutRLS returns public tables whose last known RLS state is
// off. Files must be in migration order.
func FindTablesWithoutRLS(files []SQLFile) []Table {
	t, _ := Analyze(files)
	return t
}

type event struct {
	pos  int
	kind byte // 'c' create, 'e' enable, 'd' disable, 'x' drop, 'r' rename, 's' set schema
	key  string
	name string
	// rename: the new key/name
	newKey, newName string
}

type tableState struct {
	Table
	key     string
	enabled bool
}

// Analyze is FindTablesWithoutRLS plus warnings. When a migration installs an
// event trigger that enables RLS, or a do block enables it with dynamic SQL,
// per-table checking is skipped entirely.
func Analyze(files []SQLFile) ([]Table, []string) {
	clean := make([]string, len(files))
	for i, f := range files {
		// Trigger detection looks at function bodies and strings too, because
		// the auto-enable trigger runs its ALTER TABLE as dynamic SQL.
		loose := mask(f.Content, false)
		if eventTriggerRe.MatchString(loose) && enableRLSRe.MatchString(loose) {
			return nil, []string{warnEventTrigger(f.Path)}
		}
		if doBlockDynamicEnable(loose) {
			return nil, []string{warnDynamicEnable(f.Path)}
		}
		clean[i] = mask(f.Content, true)
	}

	var order []*tableState
	live := map[string]*tableState{}
	for i, f := range files {
		for _, ev := range events(clean[i]) {
			switch ev.kind {
			case 'c':
				if live[ev.key] != nil {
					continue
				}
				s := &tableState{Table: Table{Name: ev.name, File: f.Path, Line: 1 + strings.Count(f.Content[:ev.pos], "\n")}, key: ev.key}
				live[ev.key] = s
				order = append(order, s)
			case 'e', 'd':
				if s := live[ev.key]; s != nil {
					s.enabled = ev.kind == 'e'
				}
			case 'r':
				if s := live[ev.key]; s != nil {
					delete(live, ev.key)
					s.key, s.Name = ev.newKey, ev.newName
					live[s.key] = s
				}
			case 's': // moved out of public; moving a table into public is not tracked
				delete(live, ev.key)
			case 'x':
				delete(live, ev.key)
			}
		}
	}

	var out []Table
	for _, s := range order {
		if live[s.key] == s && !s.enabled {
			out = append(out, s.Table)
		}
	}
	return out, nil
}

// doBlockDynamicEnable reports a do block whose body runs dynamic SQL
// (execute) that enables RLS, e.g. a loop over every table. loose is the
// migration with comments removed and strings kept.
func doBlockDynamicEnable(loose string) bool {
	for _, m := range doStartRe.FindAllStringSubmatchIndex(loose, -1) {
		tag := loose[m[2]:m[3]]
		body := loose[m[1]:]
		if end := strings.Index(body, tag); end >= 0 {
			body = body[:end]
		}
		if executeRe.MatchString(body) && enableRLSRe.MatchString(body) {
			return true
		}
	}
	return false
}

// events lists the statements that matter, in text order. Only tables in the
// public schema (explicit or implied) produce events.
func events(sql string) []event {
	var evs []event
	for _, m := range createRe.FindAllStringSubmatchIndex(sql, -1) {
		if m[2] >= 0 { // temp table: not exposed through the API
			continue
		}
		if key, name, ok := resolve(sql, m[4], m[5], m[6], m[7]); ok {
			evs = append(evs, event{pos: m[0], kind: 'c', key: key, name: name})
		}
	}
	for _, m := range alterRe.FindAllStringSubmatchIndex(sql, -1) {
		key, _, ok := resolve(sql, m[2], m[3], m[4], m[5])
		if !ok {
			continue
		}
		tail := sql[m[6]:m[7]]
		if r := renameRe.FindStringSubmatchIndex(tail); r != nil {
			k, n := normalize(tail[r[2]:r[3]])
			evs = append(evs, event{pos: m[0], kind: 'r', key: key, newKey: k, newName: n})
			continue
		}
		if r := schemaRe.FindStringSubmatchIndex(tail); r != nil {
			if schema, _ := normalize(tail[r[2]:r[3]]); schema != "public" {
				evs = append(evs, event{pos: m[0], kind: 's', key: key})
			}
			continue
		}
		// the enable/disable action may sit anywhere in the action list; the last one wins
		if all := rlsRe.FindAllStringSubmatch(tail, -1); len(all) > 0 {
			kind := byte('e')
			if strings.EqualFold(all[len(all)-1][1], "disable") {
				kind = 'd'
			}
			evs = append(evs, event{pos: m[0], kind: kind, key: key})
		}
	}
	for _, m := range dropRe.FindAllStringSubmatchIndex(sql, -1) {
		for _, part := range strings.Split(sql[m[2]:m[3]], ",") {
			sm := nameRe.FindStringSubmatchIndex(part)
			if sm == nil {
				continue
			}
			if key, _, ok := resolve(part, sm[2], sm[3], sm[4], sm[5]); ok {
				evs = append(evs, event{pos: m[0], kind: 'x', key: key})
			}
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].pos < evs[j].pos })
	return evs
}

// resolve turns the captured identifiers into a lookup key and display name.
// With a single identifier it is the table name; with two, schema then table.
// ok is false for tables outside the public schema.
func resolve(s string, a0, a1, b0, b1 int) (key, name string, ok bool) {
	first := s[a0:a1]
	if b0 < 0 {
		k, n := normalize(first)
		return k, n, true
	}
	schema, _ := normalize(first)
	if schema != "public" {
		return "", "", false
	}
	k, n := normalize(s[b0:b1])
	return k, n, true
}

// normalize applies Postgres folding: unquoted names are lowercased, quoted
// names keep their case. name is the text as written, without quotes.
func normalize(id string) (key, name string) {
	if strings.HasPrefix(id, `"`) {
		name = strings.ReplaceAll(id[1:len(id)-1], `""`, `"`)
		return name, name
	}
	return strings.ToLower(id), id
}

// mask returns s with comments replaced by spaces, keeping newlines so
// offsets and line numbers stay aligned with the original. Double-quoted
// identifiers are kept. With blank set it also blanks the inside of
// single-quoted strings and of dollar-quoted function/procedure bodies, so
// text that is data or runtime code never matches; a "do $$ ... $$" body is
// real DDL run at migration time and is kept. Without blank, strings and
// dollar bodies are copied untouched (comment markers inside them are not
// comments).
func mask(s string, blank bool) string {
	b := []byte(s)
	erase := func(from, to int) {
		for i := from; i < to && i < len(b); i++ {
			if b[i] != '\n' && b[i] != '\r' {
				b[i] = ' '
			}
		}
	}
	var open []string // tags of kept do-block bodies
	stmt := 0         // start of the current statement
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\'':
			j := i + 1
			for j < len(b) && b[j] != '\'' { // a doubled quote simply reopens the string
				j++
			}
			if blank {
				erase(i+1, j)
			}
			i = j + 1
		case c == '"':
			j := i + 1
			for j < len(b) && b[j] != '"' {
				j++
			}
			i = j + 1
		case c == '-' && i+1 < len(b) && b[i+1] == '-':
			j := i
			for j < len(b) && b[j] != '\n' {
				j++
			}
			erase(i, j)
			i = j
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			depth, j := 1, i+2
			for j < len(b) && depth > 0 {
				switch {
				case b[j] == '/' && j+1 < len(b) && b[j+1] == '*':
					depth++
					j += 2
				case b[j] == '*' && j+1 < len(b) && b[j+1] == '/':
					depth--
					j += 2
				default:
					j++
				}
			}
			erase(i, j)
			i = j
		case c == '$':
			tag := dollarTag(s, i)
			if tag == "" {
				i++
				break
			}
			if n := len(open); n > 0 && open[n-1] == tag { // end of a kept do body
				erase(i, i+len(tag))
				open = open[:n-1]
				i += len(tag)
				break
			}
			end := strings.Index(s[i+len(tag):], tag)
			if end < 0 {
				end = len(s) - i - len(tag) // unterminated: body runs to the end
			}
			bodyEnd := i + len(tag) + end
			if blank && doRe.MatchString(string(b[stmt:i])) {
				erase(i, i+len(tag))
				open = append(open, tag)
				i += len(tag)
				break
			}
			if blank {
				erase(i, bodyEnd+len(tag))
			}
			i = bodyEnd + len(tag)
		case c == ';':
			stmt = i + 1
			i++
		default:
			i++
		}
	}
	return string(b)
}

// dollarTag returns the "$tag$" opener at s[i], or "" if there is none.
func dollarTag(s string, i int) string {
	if i > 0 {
		if p := s[i-1]; p == '_' || p == '$' || p >= '0' && p <= '9' || p >= 'a' && p <= 'z' || p >= 'A' && p <= 'Z' || p >= 0x80 {
			return ""
		}
	}
	j := i + 1
	for j < len(s) {
		ch := s[j]
		if ch == '_' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= 0x80 || j > i+1 && ch >= '0' && ch <= '9' {
			j++
			continue
		}
		break
	}
	if j < len(s) && s[j] == '$' {
		return s[i : j+1]
	}
	return ""
}
