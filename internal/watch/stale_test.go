package watch

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func staleErr() error {
	return fmt.Errorf("RPC 1: 최신 블록이 오래되었습니다: %w", ErrStale)
}

func TestStaleBlockErrorWrapsErrStale(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(-48 * time.Hour))}
	_, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
}

// A block time that cannot be read is not a stale node.
func TestUnreadableBlockIsNotErrStale(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x", block: "null"}
	_, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL)
	if err == nil || errors.Is(err, ErrStale) {
		t.Fatalf("err = %v", err)
	}
}

// One stale node that disagrees with a fresh one stays a disagreement.
func TestStaleDisagreeingWithFreshStaysDisagreement(t *testing.T) {
	a := &fakeNode{chainID: "0x1", code: "0x6080", block: blockAt(testNow)}
	b := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(-48 * time.Hour))}
	_, err := observeAt(t, opts("contract", walletHex), a.server(t).URL, b.server(t).URL)
	if err == nil || errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want a disagreement and not ErrStale", err)
	}
	o := Compare(Baseline{Entries: map[string]Observation{"w": {"address": walletHex}}}, nil,
		map[string]error{"w": err}, Config{Targets: []Target{{Key: "w", Kind: "evm-wallet"}}})
	if len(o.Stale) != 0 || len(o.Disagreed) != 1 {
		t.Errorf("outcome = %+v", o)
	}
}

func staleOutcome(t *testing.T, err error, now Observation) Outcome {
	t.Helper()
	b := Baseline{Entries: map[string]Observation{
		"b": {"owners": "A,B", "delegate": ""},
		"a": {"owners": "A,B", "delegate": ""},
		"c": {"owners": "A,B"},
	}}
	cfg := Config{Targets: []Target{{Key: "b"}, {Key: "a"}, {Key: "c"}}}
	failed := map[string]error{
		"b": PartialError{Obs: now, Err: staleErr()},
		"a": PartialError{Obs: now, Err: staleErr()},
		"c": PartialError{Obs: now, Err: err},
	}
	return Compare(b, map[string]Observation{}, failed, cfg)
}

func TestCompareRecordsStaleSorted(t *testing.T) {
	o := staleOutcome(t, errors.New("getOwners: 되돌려졌습니다"), Observation{"owners": "A"})
	if !slices.Equal(o.Stale, []string{"a", "b"}) {
		t.Errorf("Stale = %v, want [a b] (not c: its error is not a stale node)", o.Stale)
	}
	if len(o.Changes) != 3 || len(o.Unverified) != 3 {
		t.Errorf("a stale target keeps its changes and stays unverified: %+v", o)
	}
}

func TestStaleFindingsAreSuspectButKeepIDAndSeverity(t *testing.T) {
	cfg := Config{Targets: []Target{{Key: "w", Kind: "evm-wallet"}, {Key: "x", Kind: "evm-wallet"}}}
	cases := []struct {
		name   string
		change Change
		id     string
		sev    finding.Severity
	}{
		{"owners", Change{Key: "w", Field: "owners", Old: "A,B", New: "A"}, "WA-002", finding.Critical},
		{"delegate set", Change{Key: "w", Field: "delegate", Old: "", New: delA}, "WA-001", finding.Critical},
		{"delegate removed", Change{Key: "w", Field: "delegate", Old: delA, New: ""}, "WA-006", finding.Medium},
		{"code", Change{Key: "w", Field: "code_sha256", Old: "a", New: "b"}, "WA-003", finding.High},
		{"address", Change{Key: "w", Field: "address", Old: delA, New: delB}, "WA-007", finding.High},
		{"implementation", Change{Key: "w", Field: "implementation", Old: delA, New: delB}, "WA-002", finding.Critical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := one(t, Outcome{Changes: []Change{c.change}, Stale: []string{"w"}}, cfg)
			if f.ID != c.id || f.Severity != c.sev {
				t.Errorf("got %s/%s, want %s/%s", f.ID, f.Severity, c.id, c.sev)
			}
			if f.Confidence != finding.Suspect {
				t.Errorf("confidence = %q, want suspect", f.Confidence)
			}
			for _, s := range []string{f.Title, f.Evidence} {
				if !strings.Contains(s, "멈춘 것으로 보이는 노드") {
					t.Errorf("text lacks the stale notice: %q", s)
				}
			}
			if !strings.Contains(f.Evidence, c.change.Field+": ") || !strings.Contains(f.Evidence, "노드 상태를 먼저 확인하세요") {
				t.Errorf("evidence = %q", f.Evidence)
			}
			plain := one(t, Outcome{Changes: []Change{c.change}}, cfg)
			if plain.Confidence != finding.Certain || strings.Contains(plain.Title, "멈춘") || strings.Contains(plain.Evidence, "멈춘") {
				t.Errorf("a target that is not stale must be unchanged: %+v", plain)
			}
		})
	}
	// Only the stale target is lowered.
	got := Findings(Outcome{
		Changes: []Change{{Key: "w", Field: "owners", Old: "A", New: "B"}, {Key: "x", Field: "owners", Old: "A", New: "B"}},
		Stale:   []string{"w"},
	}, cfg, nil)
	conf := map[string]finding.Confidence{}
	for _, f := range got {
		conf[f.Location] = f.Confidence
	}
	if conf["w"] != finding.Suspect || conf["x"] != finding.Certain {
		t.Errorf("confidences = %v", conf)
	}
}

// A partial read that is not a stale node keeps what it read as certain: this
// is the Safe takeover case.
func TestNonStalePartialErrorStaysCertain(t *testing.T) {
	b := Baseline{Entries: map[string]Observation{"w": {"master_copy": delA, "owners": "A"}}}
	cfg := Config{Targets: []Target{{Key: "w", Kind: "evm-wallet"}}}
	failed := map[string]error{"w": PartialError{Obs: Observation{"master_copy": delB}, Err: errors.New("getOwners: 되돌려졌습니다")}}
	o := Compare(b, nil, failed, cfg)
	if len(o.Stale) != 0 {
		t.Fatalf("Stale = %v", o.Stale)
	}
	f := one(t, o, cfg)
	if f.ID != "WA-002" || f.Confidence != finding.Certain || strings.Contains(f.Title+f.Evidence, "멈춘") {
		t.Errorf("finding = %+v", f)
	}
}

func TestStaleKeepsExitCode(t *testing.T) {
	cfg := Config{Targets: []Target{{Key: "w", Kind: "evm-wallet"}}}
	o := Outcome{Changes: []Change{{Key: "w", Field: "owners", Old: "A,B", New: "A"}}, Stale: []string{"w"}, Unverified: map[string]string{"w": "x"}}
	fs := Findings(o, cfg, nil)
	if got := ExitCode(o, fs, finding.High); got != 1 {
		t.Errorf("exit = %d, want 1", got)
	}
}

// A block dated in the future is not a node that is behind.
func TestFutureBlockIsNotErrStale(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(time.Hour))}
	_, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL)
	if err == nil || errors.Is(err, ErrStale) {
		t.Fatalf("err = %v", err)
	}
}
