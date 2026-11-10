// Package finding defines the result format shared by all checkers and reports.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Severity is ordered: a smaller value is less dangerous.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalText makes JSON carry the name ("high") instead of the integer.
func (s Severity) MarshalText() ([]byte, error) {
	if s < Info || s > Critical {
		return nil, fmt.Errorf("알 수 없는 심각도 값: %d", int(s))
	}
	return []byte(severityNames[s]), nil
}

// UnmarshalText parses a severity name via ParseSeverity.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// AtOrAbove reports whether any finding counts toward an exit code of 1:
// one at or above failOn. Info never counts, and a nil failOn (--fail-on
// none) means findings never do.
func AtOrAbove(fs []Finding, failOn *Severity) bool {
	if failOn == nil {
		return false
	}
	for _, f := range fs {
		if f.Severity != Info && f.Severity >= *failOn {
			return true
		}
	}
	return false
}

// ParseSeverity parses a severity name, ignoring case and surrounding spaces.
func ParseSeverity(s string) (Severity, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	for i, n := range severityNames {
		if n == name {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("알 수 없는 심각도: %q (info, low, medium, high, critical 중 하나)", s)
}

type Confidence string

const (
	Certain Confidence = "certain"
	Suspect Confidence = "suspect"
)

// Mapping links a finding to an external reference (e.g. a Korean regulation item).
type Mapping struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	Clause       string `json:"clause,omitempty"`
	ReviewStatus string `json:"review_status"`
	CheckedBy    string `json:"checked_by,omitempty"`
	CheckedAt    string `json:"checked_at,omitempty"`
	SourceURL    string `json:"source_url,omitempty"`
}

type Finding struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Source      string     `json:"source"`
	Severity    Severity   `json:"severity"`
	Exploited   bool       `json:"exploited"`
	Confidence  Confidence `json:"confidence"`
	Location    string     `json:"location"`
	Line        int        `json:"line"`
	Evidence    string     `json:"evidence"`
	Title       string     `json:"title"`
	ExplainKo   string     `json:"explain_ko"`
	Fix         string     `json:"fix"`
	References  []string   `json:"references"`
	Mappings    []Mapping  `json:"mappings"`
	Fingerprint string     `json:"fingerprint"`
}

// MakeFingerprint returns a stable 16-hex-char id for a finding whose identity
// is structural: a package name, a table, a key path, a digest. The line number
// is deliberately excluded so a finding keeps its identity when code moves.
// identity must never contain a secret value or any text read from a scanned
// file that could hold one: a fingerprint is published in reports and in
// .adkignore, and anyone can hash a guess. Use MakeMaskedFingerprint for those.
func MakeFingerprint(id, location, identity string) string {
	sum := sha256.Sum256([]byte(id + "\x00" + location + "\x00" + identity))
	return hex.EncodeToString(sum[:])[:16]
}

// MakeMaskedFingerprint returns a stable 16-hex-char id built from what the
// report shows, never from the source line. maskedEvidence is exactly the
// evidence string of the finding. occurrence counts the repeats of the same
// (rule id, file, masked evidence) in line order, from 0, so two lines that
// look the same once masked stay two findings. The value behind a mask is in
// no input, so a guess of it cannot be checked against the fingerprint. The
// cost: a new value in the same place keeps the same fingerprint.
func MakeMaskedFingerprint(id, location, maskedEvidence string, occurrence int) string {
	sum := sha256.Sum256([]byte(id + "\x00" + location + "\x00masked\x00" + maskedEvidence + "\x00" + strconv.Itoa(occurrence)))
	return hex.EncodeToString(sum[:])[:16]
}

// NormalizePath returns path relative to root, always with '/' separators.
func NormalizePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel)
}

// Sort orders findings by severity (descending), then exploited first,
// certain first, location, and line.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Exploited != b.Exploited {
			return a.Exploited
		}
		if (a.Confidence == Certain) != (b.Confidence == Certain) {
			return a.Confidence == Certain
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Line < b.Line
	})
}
