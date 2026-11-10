package watch

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

func cfgOf(keys ...string) Config {
	var c Config
	for _, k := range keys {
		c.Targets = append(c.Targets, Target{Key: k, Kind: "evm-wallet"})
	}
	return c
}

func TestCompare(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{
		"a":    {"x": "1", "y": "2", "gone": "g"},
		"b":    {"x": "1"},
		"fail": {"x": "1"},
		"old":  {"x": "1"},
	}}
	cur := map[string]Observation{
		"a":   {"x": "1", "y": "3", "added": "n"},
		"b":   {"x": "1"},
		"new": {"x": "1"},
	}
	failed := map[string]error{
		"fail":    errors.New("rpc 시간 초과"),
		"newfail": errors.New("연결 실패"),
	}
	o := Compare(b, cur, failed, cfgOf("a", "b", "fail", "new", "newfail"))

	wantChanges := []Change{
		{Key: "a", Field: "added", Old: "", New: "n"},
		{Key: "a", Field: "gone", Old: "g", New: ""},
		{Key: "a", Field: "y", Old: "2", New: "3"},
	}
	if !reflect.DeepEqual(o.Changes, wantChanges) {
		t.Fatalf("changes: %+v", o.Changes)
	}
	if len(o.Unverified) != 2 || o.Unverified["fail"] != "rpc 시간 초과" || o.Unverified["newfail"] != "연결 실패" {
		t.Fatalf("unverified: %+v", o.Unverified)
	}
	if !reflect.DeepEqual(o.NewTargets, []string{"new"}) {
		t.Fatalf("new: %+v", o.NewTargets)
	}
	if !reflect.DeepEqual(o.RemovedTargets, []string{"old"}) {
		t.Fatalf("removed: %+v", o.RemovedTargets)
	}
}

func TestCompareDeterministicOrder(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{
		"z": {"b": "1", "a": "1"}, "m": {"c": "1"}, "r1": {}, "r0": {},
	}}
	cur := map[string]Observation{"z": {"b": "2", "a": "2"}, "m": {"c": "2"}, "n2": {}, "n1": {}}
	for i := 0; i < 20; i++ {
		o := Compare(b, cur, nil, cfgOf("z", "m", "n2", "n1"))
		want := []Change{{"m", "c", "1", "2"}, {"z", "a", "1", "2"}, {"z", "b", "1", "2"}}
		if !reflect.DeepEqual(o.Changes, want) {
			t.Fatalf("order: %+v", o.Changes)
		}
		if !reflect.DeepEqual(o.NewTargets, []string{"n1", "n2"}) || !reflect.DeepEqual(o.RemovedTargets, []string{"r0", "r1"}) {
			t.Fatalf("lists: %+v %+v", o.NewTargets, o.RemovedTargets)
		}
	}
}

func TestCompareNoChange(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{"a": {"x": "1"}}}
	o := Compare(b, map[string]Observation{"a": {"x": "1"}}, nil, cfgOf("a"))
	if len(o.Changes)+len(o.Unverified)+len(o.NewTargets)+len(o.RemovedTargets) != 0 {
		t.Fatalf("expected empty outcome: %+v", o)
	}
}

func TestExitCode(t *testing.T) {
	high := []finding.Finding{{Severity: finding.High}}
	info := []finding.Finding{{Severity: finding.Info}}
	low := []finding.Finding{{Severity: finding.Low}}
	cases := []struct {
		name string
		o    Outcome
		fs   []finding.Finding
		want int
	}{
		{"none", Outcome{}, nil, 0},
		{"finding at threshold", Outcome{}, high, 1},
		{"below threshold", Outcome{}, low, 0},
		{"info never counts", Outcome{}, info, 0},
		{"unverified only", Outcome{Unverified: map[string]string{"a": "e"}}, nil, 2},
		{"finding beats unverified", Outcome{Unverified: map[string]string{"a": "e"}}, high, 1},
		{"new targets only", Outcome{NewTargets: []string{"n"}}, nil, 2},
		{"removed targets only", Outcome{RemovedTargets: []string{"r"}}, nil, 2},
		{"finding beats new", Outcome{NewTargets: []string{"n"}}, high, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ExitCode(c.o, c.fs, finding.High); got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
}

func TestCompareDisagreed(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{"a": {"x": "1"}, "b": {"x": "1"}}}
	failed := map[string]error{
		"a": fmt.Errorf("eth_getCode: %w", rpc.ErrDisagree),
		"b": errors.New("연결하지 못했습니다"),
	}
	o := Compare(b, nil, failed, cfgOf("a", "b"))
	if !reflect.DeepEqual(o.Disagreed, []string{"a"}) {
		t.Errorf("disagreed = %v", o.Disagreed)
	}
	if len(o.Unverified) != 2 {
		t.Errorf("a disagreeing target must also be unverified: %v", o.Unverified)
	}
}

// A target with no observation and no error must not look like "every field
// changed" or like "no change".
func TestCompareMissingObservationIsUnverified(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{"a": {"x": "1"}}}
	o := Compare(b, map[string]Observation{}, nil, cfgOf("a"))
	if len(o.Changes) != 0 || o.Unverified["a"] == "" {
		t.Errorf("outcome = %+v", o)
	}
}

// A partial observation: the fields read are diffed, the fields not read do
// not read as removed, and the target is Unverified.
func TestComparePartial(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{
		"w": {"master_copy": "a", "owners": "o", "threshold": "2", "code_sha256": "c"},
	}}
	inner := errors.New("getOwners 실패")
	failed := map[string]error{"w": fmt.Errorf("겉 오류: %w", PartialError{Obs: Observation{"master_copy": "b", "code_sha256": "c"}, Err: inner})}
	o := Compare(b, nil, failed, cfgOf("w"))
	want := []Change{{Key: "w", Field: "master_copy", Old: "a", New: "b"}}
	if !reflect.DeepEqual(o.Changes, want) {
		t.Fatalf("changes = %+v", o.Changes)
	}
	if !strings.Contains(o.Unverified["w"], "getOwners 실패") {
		t.Fatalf("unverified = %+v", o.Unverified)
	}
}

func TestComparePartialOfANewTargetIsOnlyUnverified(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{}}
	failed := map[string]error{"w": PartialError{Obs: Observation{"x": "1"}, Err: errors.New("e")}}
	o := Compare(b, nil, failed, cfgOf("w"))
	if len(o.Changes) != 0 || len(o.NewTargets) != 0 || o.Unverified["w"] == "" {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestComparePartialDisagreement(t *testing.T) {
	b := Baseline{Version: 1, Entries: map[string]Observation{"w": {"x": "1"}}}
	failed := map[string]error{"w": PartialError{Obs: Observation{"x": "2"}, Err: fmt.Errorf("q: %w", rpc.ErrDisagree)}}
	o := Compare(b, nil, failed, cfgOf("w"))
	if len(o.Changes) != 1 || len(o.Disagreed) != 1 {
		t.Fatalf("outcome = %+v", o)
	}
}
