package device

import (
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// ObserveTools reads the tools only, looked up in o.Path. It never runs one.
func ObserveTools(o Options) Snapshot {
	s := Snapshot{Entries: map[string]watch.Observation{}, Unread: map[string]string{}}
	observeTools(o, &s)
	return s
}

// sameFile: the two observations run the same file with the same content.
func sameFile(a, b watch.Observation) bool {
	return a["real"] == b["real"] && a["sha256"] == b["sha256"]
}

// CompareShell is what the shell's own PATH adds when it differs from the
// baseline's: cur is what the baseline PATH finds now, shell what the shell's
// PATH finds. A tool that runs a different file there than the baseline
// recorded is DV-101 high, or one grouped medium when it looks like an
// official upgrade against the baseline entry. A tool the shell's PATH does
// not find is nothing, so a short PATH (cron, launchd) stays quiet; one that
// runs the same file as the baseline PATH is left to Compare.
func CompareShell(base map[string]watch.Observation, cur, shell Snapshot, o Options) []finding.Finding {
	roots := rootsOf(o)
	var out []finding.Finding
	var upgraded []string
	for _, name := range ToolNames {
		k := ToolPrefix + name
		now, ok := shell.Entries[k]
		if !ok || now["state"] != "" {
			continue
		}
		atBase, found := cur.Entries[k]
		if found && atBase["state"] == "" && sameFile(atBase, now) {
			continue
		}
		old, inBase := base[k]
		if inBase && old["state"] == "" && sameFile(old, now) {
			continue
		}
		if inBase && upgradeShaped(sameShell(old), sameShell(now), roots) {
			upgraded = append(upgraded, k)
			continue
		}
		ev := "지금 셸의 PATH에서는 다른 파일이 먼저 실행됨: " + now["entry"] + " -> " + now["real"] + "; 기준값의 PATH에서는 "
		if found {
			ev += atBase["entry"] + " -> " + atBase["real"]
		} else {
			ev += "찾지 못함"
		}
		if inBase {
			ev += "; 기준값과 비교: " + strings.Join(changedParts(old, now), "; ")
		}
		out = append(out, newChangeFinding("DV-101", finding.High, k, ev, titles["DV-101"]+" (지금 셸의 PATH)", "shell\x00"+now["real"]+"\x00"+now["sha256"]))
	}
	if len(upgraded) > 0 {
		f := upgradeFinding(upgraded, base, shell.Entries)
		f.Title += " (지금 셸의 PATH)"
		f.Evidence = "지금 셸의 PATH에서 찾은 것: " + f.Evidence
		out = append(out, f)
	}
	return out
}
