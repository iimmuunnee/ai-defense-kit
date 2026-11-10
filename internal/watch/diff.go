package watch

import (
	"errors"
	"maps"
	"slices"
	"sort"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

// Change is one field whose value differs from the baseline. An empty Old
// or New means the field exists on only one side.
type Change struct {
	Key, Field, Old, New string
}

// Outcome is the result of comparing current observations with a baseline.
type Outcome struct {
	Changes        []Change
	Unverified     map[string]string // key -> why it could not be observed
	Disagreed      []string          // unverified because the RPC endpoints disagreed
	NewTargets     []string          // configured but not in the baseline
	RemovedTargets []string          // in the baseline but no longer configured
	Stale          []string          // unverified because the node looks stopped, or an exported file is old; what it said may be older than the baseline
	// Observed holds what each target returned, partial reads included, so that a
	// finding can use values that did not change. It is not written to reports.
	Observed map[string]Observation
	// Outside lists containers running an image from a registry outside the
	// target's allow list that no Change already covers.
	Outside []OutsideImage
}

// OutsideImage is one container whose image comes from outside the allow list.
// Name is "namespace/kind:workload/container"; Registries are those outside the list.
type OutsideImage struct {
	Key, Name, Registries string
}

// Compare diffs cur against b. Targets in failed are Unverified. A failure
// that is a PartialError still has the fields it read compared; a field it
// did not read is not a change. A failure wrapping ErrStale puts the key in
// Stale: what such a node read can be older than the baseline. Output is sorted by key, then field.
func Compare(b Baseline, cur map[string]Observation, failed map[string]error, cfg Config) Outcome {
	var o Outcome
	configured := make(map[string]bool, len(cfg.Targets))
	for _, t := range cfg.Targets {
		configured[t.Key] = true
	}
	keep := func(k string, obs Observation) {
		if o.Observed == nil {
			o.Observed = map[string]Observation{}
		}
		o.Observed[k] = obs
	}

	for k, err := range failed {
		if o.Unverified == nil {
			o.Unverified = map[string]string{}
		}
		o.Unverified[k] = err.Error()
		if errors.Is(err, rpc.ErrDisagree) {
			o.Disagreed = append(o.Disagreed, k)
		}
		if errors.Is(err, ErrStale) {
			o.Stale = append(o.Stale, k)
		}
	}
	sort.Strings(o.Disagreed)
	sort.Strings(o.Stale)

	keys := make([]string, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		keys = append(keys, t.Key)
	}
	sort.Strings(keys)
	for _, k := range keys {
		old, inBase := b.Entries[k]
		if err, bad := failed[k]; bad {
			var pe PartialError
			if errors.As(err, &pe) {
				keep(k, pe.Obs)
			}
			if inBase && errors.As(err, &pe) {
				o.Changes = append(o.Changes, diff(k, old, pe.Obs, slices.Sorted(maps.Keys(pe.Obs)))...)
			}
			continue
		}
		now, observed := cur[k]
		if !observed {
			// No observation and no error: neither "everything changed" nor "no change".
			if o.Unverified == nil {
				o.Unverified = map[string]string{}
			}
			o.Unverified[k] = "관측 결과가 없습니다"
			continue
		}
		keep(k, now)
		if !inBase {
			o.NewTargets = append(o.NewTargets, k)
			continue
		}
		o.Changes = append(o.Changes, Diff(k, old, now)...)
	}

	for k := range b.Entries {
		if !configured[k] {
			o.RemovedTargets = append(o.RemovedTargets, k)
		}
	}
	sort.Strings(o.RemovedTargets)
	o.Outside = outsideImages(cfg, o)
	return o
}

// Diff compares two complete observations of one target. Output is sorted by field.
func Diff(key string, old, now Observation) []Change {
	fields := slices.Collect(maps.Keys(old))
	fields = append(fields, slices.Collect(maps.Keys(now))...)
	slices.Sort(fields)
	return diff(key, old, now, slices.Compact(fields))
}

// diff compares the named fields, which are sorted. A field that is empty on
// one side and absent on the other holds the same nothing: it is not a change.
func diff(key string, old, now Observation, fields []string) []Change {
	var out []Change
	for _, f := range fields {
		if old[f] != now[f] {
			out = append(out, Change{Key: key, Field: f, Old: old[f], New: now[f]})
		}
	}
	return out
}

// ExitCode: 1 if a finding is at or above failOn (Info never counts),
// else 2 if anything is unverified, new or removed, else 0.
func ExitCode(o Outcome, fs []finding.Finding, failOn finding.Severity) int {
	return ExitCodeFor(o, fs, &failOn)
}

// ExitCodeFor is ExitCode with a nil failOn meaning --fail-on none: findings
// never make it 1, while the unverified, new and removed targets still make it 2.
func ExitCodeFor(o Outcome, fs []finding.Finding, failOn *finding.Severity) int {
	if finding.AtOrAbove(fs, failOn) {
		return 1
	}
	if len(o.Unverified) > 0 || len(o.NewTargets) > 0 || len(o.RemovedTargets) > 0 {
		return 2
	}
	return 0
}
