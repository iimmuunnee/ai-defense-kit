package report

import (
	"encoding/json"
	"io"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// WriteJSON writes r as JSON indented by two spaces. Empty lists are written
// as [] rather than null so consumers can iterate without checks.
func WriteJSON(w io.Writer, r Report) error {
	r.Stacks = orEmpty(r.Stacks)
	r.Findings = append(make([]finding.Finding, 0, len(r.Findings)), r.Findings...)
	for i := range r.Findings {
		r.Findings[i].References = orEmpty(r.Findings[i].References)
		r.Findings[i].Mappings = orEmpty(r.Findings[i].Mappings)
	}
	r.Checks = append(make([]checker.CheckStatus, 0, len(r.Checks)), r.Checks...)
	for i := range r.Checks {
		r.Checks[i].Warnings = orEmpty(r.Checks[i].Warnings)
	}
	if r.Kind == "" {
		r.Kind = KindCode
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if r.isAssets() {
		// The outer field wins over Report.Assets, so assets mode always
		// writes the list (as [] when empty) while code mode leaves it out.
		return enc.Encode(struct {
			Report
			Assets []AssetRow `json:"assets"`
		}{r, orEmpty(r.Assets)})
	}
	if r.Kind == KindDevice {
		// A computer has no stack list and no git commit. The outer fields
		// win over Report's and, empty, are left out.
		return enc.Encode(struct {
			Report
			Stacks    []string `json:"stacks,omitempty"`
			GitCommit string   `json:"git_commit,omitempty"`
		}{Report: r})
	}
	return enc.Encode(r)
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
