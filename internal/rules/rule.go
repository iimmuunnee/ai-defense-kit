// Package rules implements the YAML rule engine.
package rules

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Match describes when a rule fires.
type Match struct {
	Scope        string   `yaml:"scope"`
	Files        []string `yaml:"files"`
	ExcludeFiles []string `yaml:"exclude_files"` // files that match files but are left out (tests, deploy tooling)
	HasAny       []string `yaml:"has_any"`
	HasAnyRegex  []string `yaml:"has_any_regex"`
	MissingAll   []string `yaml:"missing_all"`
	MissingRegex []string `yaml:"missing_all_regex"`
	RequireAll   []string `yaml:"require_all"`
	SkipLine     []string `yaml:"skip_line_regex"` // scope: line only
	Mask         []string `yaml:"mask_regex"`      // scope: line only; removed before has_any_regex, except a group named keep
	// RegexRequires: has_any_regex runs only where one of these literals appears
	// (the line for scope: line, the file otherwise). Each must be something every
	// match of those regexes contains.
	RegexRequires []string `yaml:"regex_requires"`
	GateFiles     []string `yaml:"gate_files"` // files that need a gate_regex match before the rule looks at them
	GateRegex     []string `yaml:"gate_regex"`
}

// Reference is a source the rule was written from.
type Reference struct {
	URL       string `yaml:"url"`
	CheckedAt string `yaml:"checked_at"`
}

// Rule is one YAML rule file.
type Rule struct {
	ID         string      `yaml:"id"`
	Title      string      `yaml:"title"`
	Stacks     []string    `yaml:"stacks"`
	Severity   string      `yaml:"severity"`
	Match      Match       `yaml:"match"`
	Explain    string      `yaml:"explain"`
	Fix        string      `yaml:"fix"`
	Mappings   []string    `yaml:"mappings"`
	Confidence string      `yaml:"confidence"`
	References []Reference `yaml:"references"`
	// HideValues is for rules whose lines can hold a secret: evidence shows no
	// part of a value (not even the 4-character prefix) and the fingerprint is
	// made from that hidden form, so neither reveals or depends on the value.
	HideValues bool `yaml:"hide_values"`

	severity finding.Severity
	hasRe    []*regexp.Regexp
	missRe   []*regexp.Regexp
	skipRe   []*regexp.Regexp
	maskRe   []*regexp.Regexp
	gateRe   []*regexp.Regexp
}

// Load reads every *.yaml under rules/ in fsys and validates it.
func Load(fsys fs.FS) ([]Rule, error) {
	var out []Rule
	seen := map[string]string{}
	err := fs.WalkDir(fsys, "rules", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("%s: 읽을 수 없음: %w", p, err)
		}
		var r Rule
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&r); err != nil {
			return fmt.Errorf("%s: 규칙 형식 오류: %w", p, err)
		}
		if err := r.validate(fsys); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if prev, dup := seen[r.ID]; dup {
			return fmt.Errorf("%s: id %q가 %s와 중복됨", p, r.ID, prev)
		}
		seen[r.ID] = p
		out = append(out, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func compileAll(key string, pats []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("키 %s: 잘못된 정규식 %q: %w", key, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func (r *Rule) validate(fsys fs.FS) error {
	switch {
	case r.ID == "":
		return fmt.Errorf("필수 키 id가 없음")
	case r.Title == "":
		return fmt.Errorf("필수 키 title이 없음")
	case r.Severity == "":
		return fmt.Errorf("필수 키 severity가 없음")
	case len(r.Match.Files) == 0:
		return fmt.Errorf("필수 키 match.files가 없음")
	case len(r.Match.HasAny) == 0 && len(r.Match.HasAnyRegex) == 0:
		return fmt.Errorf("필수 키 match.has_any 또는 match.has_any_regex가 없음")
	}
	var err error
	if r.hasRe, err = compileAll("match.has_any_regex", r.Match.HasAnyRegex); err != nil {
		return err
	}
	if r.skipRe, err = compileAll("match.skip_line_regex", r.Match.SkipLine); err != nil {
		return err
	}
	if len(r.skipRe) > 0 && r.Match.Scope != "line" {
		return fmt.Errorf("키 match.skip_line_regex: scope가 line일 때만 쓸 수 있음")
	}
	if r.maskRe, err = compileAll("match.mask_regex", r.Match.Mask); err != nil {
		return err
	}
	if len(r.Match.RegexRequires) > 0 && len(r.hasRe) == 0 {
		return fmt.Errorf("키 match.regex_requires: has_any_regex와 함께 써야 함")
	}
	if len(r.maskRe) > 0 && r.Match.Scope != "line" {
		return fmt.Errorf("키 match.mask_regex: scope가 line일 때만 쓸 수 있음")
	}
	if r.missRe, err = compileAll("match.missing_all_regex", r.Match.MissingRegex); err != nil {
		return err
	}
	if r.gateRe, err = compileAll("match.gate_regex", r.Match.GateRegex); err != nil {
		return err
	}
	if (len(r.gateRe) > 0) != (len(r.Match.GateFiles) > 0) {
		return fmt.Errorf("키 match.gate_files, match.gate_regex: 둘을 함께 써야 함")
	}
	for _, pat := range r.Match.GateFiles {
		if !doublestar.ValidatePattern(pat) {
			return fmt.Errorf("키 match.gate_files: 잘못된 패턴 %q", pat)
		}
	}
	for _, pat := range r.Match.Files {
		if !doublestar.ValidatePattern(pat) {
			return fmt.Errorf("키 match.files: 잘못된 패턴 %q", pat)
		}
	}
	for _, pat := range r.Match.ExcludeFiles {
		if !doublestar.ValidatePattern(pat) {
			return fmt.Errorf("키 match.exclude_files: 잘못된 패턴 %q", pat)
		}
	}
	sev, err := finding.ParseSeverity(r.Severity)
	if err != nil {
		return fmt.Errorf("키 severity: %w", err)
	}
	r.severity = sev
	switch r.Match.Scope {
	case "":
		r.Match.Scope = "file"
	case "file", "repo", "line":
	default:
		return fmt.Errorf("키 match.scope: %q는 허용되지 않음 (file, line 또는 repo)", r.Match.Scope)
	}
	switch r.Confidence {
	case "", "high", "medium", "low":
	default:
		return fmt.Errorf("키 confidence: %q는 허용되지 않음 (high, medium, low)", r.Confidence)
	}
	if r.Explain != "" {
		if _, err := fs.Stat(fsys, r.Explain); err != nil {
			return fmt.Errorf("키 explain: %q 경로가 없음", r.Explain)
		}
	}
	if r.Fix != "" {
		if st, err := fs.Stat(fsys, path.Clean(r.Fix)); err != nil || !st.IsDir() {
			return fmt.Errorf("키 fix: %q 폴더가 없음", r.Fix)
		}
	}
	return nil
}
