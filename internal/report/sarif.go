package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	sarifSchemaURL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
	sarifInfoURL   = "https://github.com/iimmuunnee/ai-defense-kit"

	// GitHub documents no limit for message and help text; these are our own
	// ceilings. shortDescription is capped at 1024 characters by GitHub.
	maxMessageRunes = 6000
	maxHelpRunes    = 20000
	maxShortRunes   = 1024

	truncatedNote = "… 전체 내용은 리포트 참고"

	tagSecurity  = "security"
	tagExploited = "actively-exploited"
	tagSupply    = "supply-chain"
	exploitedKo  = "[실제 공격 중] "
)

// The SARIF structs below are plain structs, not maps, so key order is fixed
// and the output is byte-for-byte reproducible.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	Properties  sarifRunProps     `json:"properties"`
}

type sarifRunProps struct {
	GitCommit string `json:"gitCommit"`
	GitDirty  string `json:"gitDirty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifHelp       `json:"help"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProps  `json:"properties"`
}

type sarifResultProps struct {
	Confidence string   `json:"confidence"`
	Severity   string   `json:"severity"`
	Tags       []string `json:"tags,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
	// URIBaseID is empty for a device report: its paths are on this computer,
	// not in a repository.
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	EndTimeUTC                 string              `json:"endTimeUtc,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// sarifLevel maps an adk severity to a SARIF result level.
func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the GitHub security-severity score; "" for info.
func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "9.5"
	case finding.High:
		return "8.0"
	case finding.Medium:
		return "5.5"
	case finding.Low:
		return "2.0"
	}
	return ""
}

// sarifRuleID keeps secrets findings of different Kind apart: the same
// SECRET-* ID is used for current code (high) and git history (medium), and
// security-severity is per rule. Fingerprints and .adkignore are unaffected.
func sarifRuleID(f finding.Finding) string {
	if f.Source == "secrets" && f.Kind != "" {
		return f.ID + "/" + f.Kind
	}
	return f.ID
}

// truncateRunes cuts s to at most max runes (never inside a character) and
// marks the cut.
func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	keep := max - utf8.RuneCountInString(truncatedNote)
	if keep < 0 {
		keep = 0
	}
	return string([]rune(s)[:keep]) + truncatedNote
}

func reviewStatusKo(m finding.Mapping) string {
	switch m.ReviewStatus {
	case "checked":
		return "원문 대조함"
	case "expert":
		return "전문가 검수함"
	}
	return "검수 전"
}

func sarifMessage(f finding.Finding, scrub func(string) string) string {
	// SARIF reads [text](uri) in message text as an embedded link, so the
	// brackets of text that comes from the scanned repository are escaped.
	title := escapeBrackets(oneLine(SafeText(f.Title)))
	if f.Exploited {
		title = exploitedKo + title
	}
	lines := []string{title}
	if e := strings.TrimSpace(f.Evidence); e != "" {
		lines = append(lines, "근거: "+escapeBrackets(SafeText(e)))
	}
	if fix := strings.TrimSpace(f.Fix); fix != "" {
		lines = append(lines, "수정 방법: "+fix)
	}
	if len(f.Mappings) > 0 {
		parts := make([]string, 0, len(f.Mappings))
		for _, m := range f.Mappings {
			parts = append(parts, fmt.Sprintf("%s (%s)", oneLine(m.ID), reviewStatusKo(m)))
		}
		lines = append(lines, "국내 기준: "+strings.Join(parts, ", "))
	}
	return truncateRunes(scrub(strings.Join(lines, "\n")), maxMessageRunes)
}

// escapeBrackets escapes backslash, then square brackets, with a backslash:
// the escape set of SARIF 2.1.0 section 3.11.6, so text from the scanned
// repository cannot form an embedded link.
func escapeBrackets(s string) string {
	return strings.NewReplacer("\\", "\\\\", "[", "\\[", "]", "\\]").Replace(s)
}

// sarifURI turns a repo-relative path into a URI reference: each '/'-separated
// piece is percent-encoded, the separators stay.
func sarifURI(prefix, loc string) string {
	parts := strings.Split(prefix+loc, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// safeLocation makes a finding location safe for the URI. A relative location
// is returned as it is (slashes normalized, a leading "./" dropped): no text is
// replaced in it, so a folder named like the scan root stays intact. An
// absolute location (drive letter, UNC or leading separator, either slash
// style) inside root becomes relative to root; any other absolute location
// becomes its last element. The full path never reaches the URI.
func safeLocation(loc, root string) string {
	p := strings.ReplaceAll(loc, `\`, "/")
	if !isAbsPath(p) {
		return strings.TrimPrefix(p, "./")
	}
	p = path.Clean(p)
	r := strings.TrimRight(strings.ReplaceAll(root, `\`, "/"), "/")
	if r != "" && isAbsPath(r) {
		r = path.Clean(r)
		fold := (len(r) >= 2 && r[1] == ':') || strings.HasPrefix(r, "//")
		prefix := r
		if prefix != "/" {
			prefix += "/"
		}
		if len(p) > len(prefix) {
			head := p[:len(prefix)]
			if head == prefix || (fold && strings.EqualFold(head, prefix)) {
				return p[len(prefix):]
			}
		}
	}
	return p[strings.LastIndex(p, "/")+1:]
}

// isAbsPath reports whether p (forward slashes) starts with a separator or a
// drive letter and separator.
func isAbsPath(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/' && unicode.IsLetter(rune(p[0]))
}

// ruleAcc collects what one rule needs from all of its results.
type ruleAcc struct {
	id        string
	first     finding.Finding
	maxSev    finding.Severity
	suspect   bool
	exploited bool
	supply    bool
}

// WriteSARIF writes r as SARIF 2.1.0 with Korean text. Findings hidden by
// .adkignore are not in r.Findings and so never appear. Findings are sorted
// on a copy with a tie-break, so the order they arrive in does not change the
// output.
func WriteSARIF(w io.Writer, r Report) error {
	scrub := func(s string) string { return Scrub(s, r.ScanRoot, r.PrivatePaths) }

	var accs []*ruleAcc
	index := map[string]int{}
	results := []sarifResult{}
	seen := map[string]int{}
	for _, f := range canonicalFindings(r.Findings) {
		id := sarifRuleID(f)
		i, ok := index[id]
		if !ok {
			i = len(accs)
			index[id] = i
			accs = append(accs, &ruleAcc{id: id, first: f, maxSev: f.Severity})
		}
		a := accs[i]
		if f.Severity > a.maxSev {
			a.maxSev = f.Severity
		}
		if f.Confidence != finding.Certain {
			a.suspect = true
		}
		if f.Exploited {
			a.exploited = true
		}
		if f.Kind == "malicious-lib" || strings.HasPrefix(f.ID, "AR-") {
			a.supply = true
		}

		res := sarifResult{
			RuleID:     id,
			RuleIndex:  i,
			Level:      sarifLevel(f.Severity),
			Message:    sarifText{Text: sarifMessage(f, scrub)},
			Properties: sarifResultProps{Confidence: string(f.Confidence), Severity: f.Severity.String()},
		}
		if f.Fingerprint != "" {
			// Distinct findings can share a fingerprint, so primaryLocationLineHash
			// (the only key GitHub uses) gets an occurrence counter.
			seen[f.Fingerprint]++
			res.PartialFingerprints = map[string]string{
				"adkFingerprint/v1":       f.Fingerprint,
				"primaryLocationLineHash": fmt.Sprintf("%s:%d", f.Fingerprint, seen[f.Fingerprint]),
			}
		}
		if f.Exploited {
			res.Properties.Tags = []string{tagExploited}
		}
		if safe := safeLocation(f.Location, r.ScanRoot); safe != "" {
			loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: sarifURI(r.RepoPrefix, safe), URIBaseID: "%SRCROOT%"}}
			if r.Kind == KindDevice {
				loc.ArtifactLocation.URIBaseID = ""
			}
			if f.Line > 0 {
				loc.Region = &sarifRegion{StartLine: f.Line}
			}
			res.Locations = []sarifLocation{{PhysicalLocation: loc}}
		}
		results = append(results, res)
	}

	rules := []sarifRule{}
	for _, a := range accs {
		tags := []string{tagSecurity}
		if a.exploited {
			tags = append(tags, tagExploited)
		}
		if a.supply {
			tags = append(tags, tagSupply)
		}
		// Secrets confidence depends on the file path, so that rule is fixed
		// at medium to keep its content the same from run to run.
		precision := "high"
		if a.suspect || a.first.Source == "secrets" {
			precision = "medium"
		}
		title := truncateRunes(oneLine(SafeText(scrub(a.first.Title))), maxShortRunes)
		help := scrub(a.first.ExplainKo)
		tail := "\n\n" + Disclaimer
		help = strings.TrimSpace(help)
		if help == "" {
			help = Disclaimer
		} else {
			help = truncateRunes(help, maxHelpRunes-utf8.RuneCountInString(tail)) + tail
		}
		rules = append(rules, sarifRule{
			ID:                   a.id,
			ShortDescription:     sarifText{Text: title},
			FullDescription:      sarifText{Text: title},
			Help:                 sarifHelp{Text: help, Markdown: help},
			DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(a.maxSev)},
			Properties:           sarifRuleProps{Tags: tags, Precision: precision, SecuritySeverity: securitySeverity(a.maxSev)},
		})
	}

	inv := sarifInvocation{ExecutionSuccessful: true}
	if !r.ScannedAt.IsZero() {
		inv.EndTimeUTC = r.ScannedAt.UTC().Format(time.RFC3339)
	}
	notify := func(level, text string) {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{
			Level: level, Message: sarifText{Text: escapeBrackets(SafeText(scrub(text)))},
		})
	}
	for _, c := range r.Checks {
		switch c.Status {
		case checker.StatusFailed:
			inv.ExecutionSuccessful = false
			notify("error", fmt.Sprintf("%s (실패): %s", c.Name, c.Error))
		case checker.StatusSkipped:
			notify("warning", fmt.Sprintf("%s (건너뜀): %s", c.Name, c.Error))
		}
		for _, warn := range c.Warnings {
			notify("warning", fmt.Sprintf("%s: %s", c.Name, warn))
		}
	}

	dirty := r.GitDirty
	if dirty == "" {
		dirty = DirtyUnknown
	}
	log := sarifLog{
		Schema:  sarifSchemaURL,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "adk", Version: r.ToolVersion, InformationURI: sarifInfoURL, Rules: rules,
			}},
			Invocations: []sarifInvocation{inv},
			Results:     results,
			Properties:  sarifRunProps{GitCommit: r.GitCommit, GitDirty: dirty},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
