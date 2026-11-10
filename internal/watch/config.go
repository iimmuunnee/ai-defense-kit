// Package watch compares observations of targets (wallets and the like)
// against a saved baseline and reports what changed.
package watch

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Target is one thing to watch. Key identifies it in the baseline.
type Target struct {
	Key     string         `yaml:"key"`
	Kind    string         `yaml:"kind"`
	Options map[string]any `yaml:"options"`
}

// Config is the parsed watch configuration.
type Config struct {
	Targets []Target `yaml:"targets"`
}

// Observation maps a field name to its normalized value.
type Observation map[string]string

// Observer reads the current state of targets of one kind. It must not
// write to the target.
//
// Observe returns one of three things:
//   - a complete Observation and a nil error;
//   - nil and a PartialError, when some fields were read and a later read
//     failed. Compare still diffs the fields that were read, so a change seen
//     before the failure is reported, and marks the target Unverified;
//   - nil and any other error, when nothing could be read.
//
// A failure must never be returned as an Observation with a field missing or
// empty: that reads as a change, or as no change.
type Observer interface {
	Kind() string
	Observe(ctx context.Context, t Target) (Observation, error)
}

// PartialError says an observation is incomplete: Obs holds only the fields
// that were really read, and Err says why the rest were not. init and accept
// refuse a target that returns it, unless Err wraps ErrSomeUnread.
type PartialError struct {
	Obs Observation
	Err error
}

func (e PartialError) Error() string { return e.Err.Error() }
func (e PartialError) Unwrap() error { return e.Err }

// errDeadline is the Err of a PartialError from an observer that ran out of
// time. It matches context.DeadlineExceeded under errors.Is.
var errDeadline error = deadlineError{}

type deadlineError struct{}

func (deadlineError) Error() string        { return "제한 시간 안에 다 읽지 못했습니다" }
func (deadlineError) Is(target error) bool { return target == context.DeadlineExceeded }

// knownKinds lists the target kinds LoadConfig accepts.
var knownKinds = func() map[string]bool {
	m := map[string]bool{}
	for k := range kinds {
		m[k] = true
	}
	return m
}()

// LoadConfig reads a watch config. Unknown fields, unknown kinds, unknown
// options of a kind, empty keys and duplicate keys are errors.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("설정 파일을 읽을 수 없습니다: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("설정 파일 형식이 올바르지 않습니다: %w", err)
	}
	seen := make(map[string]bool, len(cfg.Targets))
	for i, t := range cfg.Targets {
		if t.Key == "" {
			return Config{}, fmt.Errorf("설정 오류: %d번째 대상의 key가 비어 있습니다", i+1)
		}
		if !knownKinds[t.Kind] {
			return Config{}, fmt.Errorf("설정 오류: 대상 %q의 kind %q를 알 수 없습니다", t.Key, t.Kind)
		}
		if seen[t.Key] {
			return Config{}, fmt.Errorf("설정 오류: key %q가 중복되었습니다", t.Key)
		}
		seen[t.Key] = true
		verr := kinds[t.Kind].validate(t.Options)
		if verr != nil {
			return Config{}, fmt.Errorf("설정 오류: 대상 %q: %w", t.Key, verr)
		}
	}
	return cfg, nil
}
