package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os/user"
	"slices"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/report"
	"github.com/iimmuunnee/ai-defense-kit/internal/safeio"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

type historyChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

type historyEntry struct {
	Time    string          `json:"time"`
	OSUser  string          `json:"os_user"`
	Key     string          `json:"key"`
	Note    string          `json:"note"`
	OldHash string          `json:"old_hash"`
	NewHash string          `json:"new_hash"`
	Changes []historyChange `json:"changes"`
}

func osUser() string {
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return u.Username
	}
	return "unknown"
}

// appendJSONL adds one line to a record file. It only ever appends.
func appendJSONL(path string, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return safeio.AppendFile(path, 0o600, append(line, '\n'))
}

// expectFlag collects repeated --expect field=value options.
type expectFlag []string

func (e *expectFlag) String() string { return strings.Join(*e, ",") }
func (e *expectFlag) Set(v string) error {
	*e = append(*e, v)
	return nil
}

func expectMatches(got, want string) bool {
	return strings.EqualFold(got, strings.TrimSpace(want))
}

// splitExpect reads one --expect. Both a field name and a value can hold "=", so
// every "=" is tried: the left side must be a field of the baseline or of what
// was read. When two readings are possible the one that is true is taken;
// readings is how many there were, and field is empty when none could be taken.
func splitExpect(e string, old, read watch.Observation) (field, want string, readings int) {
	var fields, wants []string
	for i := 0; i < len(e); i++ {
		if e[i] != '=' {
			continue
		}
		left := e[:i]
		_, inOld := old[left]
		_, inRead := read[left]
		if inOld || inRead {
			fields, wants = append(fields, left), append(wants, e[i+1:])
		}
	}
	if len(fields) == 1 {
		return fields[0], wants[0], 1
	}
	for i := range fields {
		if expectMatches(read[fields[i]], wants[i]) {
			return fields[i], wants[i], len(fields)
		}
	}
	return "", "", len(fields)
}

// checkExpected compares --expect values with what was just read, and reports
// which fields they name. Hex case does not matter. An empty value names a
// removal. A field neither side has is a refusal, so a typo cannot pass as
// "expected empty"; so is one in unread, whose value nobody has seen.
func checkExpected(expects []string, old, read watch.Observation, unread []string) (named map[string]bool, bad []string) {
	named = map[string]bool{}
	for _, e := range expects {
		field, want, readings := splitExpect(e, old, read)
		switch {
		case readings == 0:
			bad = append(bad, fmt.Sprintf("%s: 이 대상에 없는 항목입니다", report.SafeText(e)))
			continue
		case field == "":
			bad = append(bad, fmt.Sprintf("%s: 항목 이름을 %d가지로 읽을 수 있는데 어느 쪽도 지금 값과 맞지 않습니다", report.SafeText(e), readings))
			continue
		}
		named[field] = true
		got, has := read[field]
		switch {
		case slices.Contains(unread, field):
			bad = append(bad, fmt.Sprintf("%s: 이번에 읽지 못한 항목이라 값을 확인할 수 없습니다", report.SafeText(field)))
		case has && !expectMatches(got, want), !has && strings.TrimSpace(want) != "":
			bad = append(bad, fmt.Sprintf("%s: 기대 %s, 지금 %s", report.SafeText(field), report.SafeText(shownValue(want)), report.SafeText(shownValue(got))))
		}
	}
	return named, bad
}

func shownValue(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(없음)"
	}
	return s
}

// warnKept says which baseline fields stayed as they were because this read
// did not reach them. A change in them is reported once they can be read.
func warnKept(key string, kept []string, sc *scrubber, stderr io.Writer) {
	if len(kept) > 0 {
		fmt.Fprintf(stderr, "경고: %s: 이번에 읽지 못한 항목은 기준값의 값을 그대로 두었습니다: %s. 읽을 수 있게 될 때까지 check는 종료 코드 2입니다.\n",
			report.SafeText(key), report.SafeText(sc.clean(strings.Join(kept, ", "))))
	}
}

func watchAccept(ctx context.Context, cfg watch.Config, opt watchOptions, key string, sc *scrubber, stdout, stderr io.Writer) int {
	note := strings.TrimSpace(opt.note)
	if note == "" {
		fmt.Fprintln(stderr, "--note가 필요합니다. 받아들이는 이유를 적으세요: adk watch accept <key> --note \"사유\"")
		return 2
	}
	for _, e := range opt.expects {
		if field, _, ok := strings.Cut(e, "="); !ok || field == "" {
			fmt.Fprintf(stderr, "--expect 값이 올바르지 않습니다: %q (항목=값 형식이어야 합니다)\n", report.SafeText(e))
			return 2
		}
	}
	base, err := watch.LoadBaseline(opt.baseline, opt.pin)
	if err != nil {
		fmt.Fprintf(stderr, "기준값을 확인하지 못했습니다: %v\n", err)
		return 2
	}
	var target *watch.Target
	for i := range cfg.Targets {
		if cfg.Targets[i].Key == key {
			target = &cfg.Targets[i]
		}
	}
	old, inBase := base.Entries[key]
	if target == nil && !inBase {
		fmt.Fprintf(stderr, "설정에도 기준값에도 없는 key입니다: %s\n", report.SafeText(key))
		return 2
	}
	if target == nil && len(opt.expects) > 0 {
		fmt.Fprintf(stderr, "%s은(는) 설정에서 빠져 읽을 수 없으므로 --expect와 맞춰 볼 수 없습니다. 기준값을 바꾸지 않았습니다.\n", report.SafeText(key))
		return 2
	}

	entries := maps.Clone(base.Entries)
	var now, read watch.Observation
	var kept []string // baseline fields left as they are, because they were not read
	if target != nil {
		cur, failed := collect(ctx, []watch.Target{*target}, sc, opt)
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, msgCancelled)
			return 2
		}
		read = cur[key]
		if err := failed[key]; err != nil {
			obs, _, ok := watch.SomeUnread(err)
			if !ok {
				fmt.Fprintf(stderr, "%s을(를) 다 읽지 못해 기준값을 바꾸지 않았습니다: 확인 못 함: %s\n", report.SafeText(key), report.SafeText(err.Error()))
				return 2
			}
			read = obs
			for f := range old {
				if _, has := read[f]; !has {
					kept = append(kept, f)
				}
			}
			slices.Sort(kept)
		}
		now = maps.Clone(read)
		for _, f := range kept {
			now[f] = old[f]
		}
		named, bad := checkExpected(opt.expects, old, read, kept)
		if len(bad) > 0 {
			fmt.Fprintf(stderr, "%s의 지금 값이 --expect와 달라 기준값을 바꾸지 않았습니다.\n", report.SafeText(key))
			for _, line := range bad {
				fmt.Fprintf(stderr, "  - %s\n", line)
			}
			return 2
		}
		if len(opt.expects) > 0 {
			// The reviewer's list is the whole of what may enter the baseline.
			var unnamed []watch.Change
			for _, c := range watch.Diff(key, old, now) {
				if !named[c.Field] {
					unnamed = append(unnamed, c)
				}
			}
			if len(unnamed) > 0 {
				fmt.Fprintf(stderr, "%s에서 --expect에 적지 않은 항목이 달라져 기준값을 바꾸지 않았습니다. --expect를 주면 바뀌거나 생기거나 사라지는 항목을 모두 적어야 합니다(사라지는 항목은 값을 비워 `항목=`으로).\n", report.SafeText(key))
				for _, c := range unnamed {
					fmt.Fprintf(stderr, "  - %s: %s -> %s\n", report.SafeText(c.Field), report.SafeText(shownValue(c.Old)), report.SafeText(shownValue(c.New)))
				}
				return 2
			}
		}
		if inBase && len(watch.Diff(key, old, now)) == 0 {
			if len(kept) > 0 {
				fmt.Fprintf(stdout, "%s의 읽은 값은 기준값과 같습니다. 바꾼 것이 없습니다.\n", report.SafeText(key))
			} else {
				fmt.Fprintf(stdout, "%s은(는) 이미 기준값과 같습니다. 바꾼 것이 없습니다.\n", report.SafeText(key))
			}
			warnKept(key, kept, sc, stderr)
			return 0
		}
		// A first-time target, and one whose identity changed (WA-007), are new
		// claims about what is being watched: they get the same plausibility
		// check as init. An ordinary accept does not, so a contract that lost its
		// code can still be accepted after review.
		if !inBase || watch.IdentityChanged(target.Kind, old, now) {
			if err := watch.CheckInitial(*target, now); err != nil {
				fmt.Fprintf(stderr, "기준값을 바꾸지 않았습니다: %s\n", report.SafeText(err.Error()))
				return 2
			}
		}
		entries[key] = now
	} else {
		delete(entries, key)
	}

	nb := base
	nb.Entries = entries
	changes := []historyChange{}
	for _, c := range watch.Diff(key, old, now) {
		changes = append(changes, historyChange{Field: c.Field, Old: c.Old, New: c.New})
	}
	entry := historyEntry{Time: watchNow().UTC().Format(time.RFC3339), OSUser: osUser(), Key: key, Note: note, Changes: changes}
	sum, ok := commitAccept(opt.baseline, opt.historyPath(), nb, []historyEntry{entry}, stderr)
	if !ok {
		return 2
	}
	if target != nil {
		warnBaseline(*target, read, stderr)
	}
	warnKept(key, kept, sc, stderr)
	fmt.Fprintf(stdout, "%s을(를) 기준값에 반영했습니다. 기록: %s\nSHA-256: %s\n", report.SafeText(key), opt.historyPath(), sum)
	fmt.Fprintln(stdout, "반영한 값:")
	for _, c := range changes {
		fmt.Fprintf(stdout, "  %s: %s -> %s\n", report.SafeText(c.Field), report.SafeText(shownValue(c.Old)), report.SafeText(shownValue(c.New)))
	}
	fmt.Fprintln(stdout, "새 SHA-256을 기준값 파일과 따로 적어 두세요.")
	return 0
}

// commitAccept is the common tail of watch accept and device accept: one
// history line per record, then the new baseline. History comes first, so
// that no baseline change goes unrecorded. It fills in the baseline's SHA-256
// before and after, and returns the saved file's.
func commitAccept(baselinePath, historyPath string, nb watch.Baseline, records []historyEntry, stderr io.Writer) (string, bool) {
	oldHash, err := watch.FileSHA256(baselinePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", false
	}
	newHash, err := nb.SHA256()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", false
	}
	for _, r := range records {
		r.OldHash, r.NewHash = oldHash, newHash
		if err := appendJSONL(historyPath, r); err != nil {
			fmt.Fprintf(stderr, "기록 파일에 쓰지 못해 기준값을 바꾸지 않았습니다: %v\n", err)
			return "", false
		}
	}
	sum, err := nb.Save(baselinePath)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n기록 파일에는 이 변경이 남았지만 기준값은 바뀌지 않았습니다. 기록의 마지막 줄을 확인하세요.\n", err)
		return "", false
	}
	return sum, true
}
