// Package report renders scan results as Korean Markdown or JSON.
package report

import (
	"fmt"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Disclaimer is the sentence that ends every report.
const Disclaimer = "이 리포트는 법률 자문이 아닙니다. 국내 기준 연결은 참고용이며, 최종 판단은 전문가와 확인하세요."

// HidingWarning is shown when a repository's .adkignore hid n findings of a scan
// run without --untrusted.
func HidingWarning(n int) string {
	return fmt.Sprintf(".adkignore가 결과 %d개를 숨겼습니다. 받은 코드라면 --untrusted로 다시 점검하세요.", n)
}

// Report kinds. An empty Kind means KindCode.
const (
	KindCode   = "code"   // adk scan: a source folder
	KindAssets = "assets" // adk assets: names found in certificate transparency logs
	KindDevice = "device" // adk device: this computer, not a source folder
)

// Report is everything one scan produced.
type Report struct {
	Kind        string                `json:"kind"`
	Target      string                `json:"target"`
	Stacks      []string              `json:"stacks"`
	ScannedAt   time.Time             `json:"scanned_at"`
	ToolVersion string                `json:"tool_version"`
	GitCommit   string                `json:"git_commit"`
	Findings    []finding.Finding     `json:"findings"`
	Ignored     int                   `json:"ignored"` // findings hidden by .adkignore
	Checks      []checker.CheckStatus `json:"checks"`

	// Assets mode only.
	KnownList string     `json:"known_list,omitempty"` // --known file, if given
	Assets    []AssetRow `json:"assets,omitempty"`     // details for Findings, matched by Fingerprint

	// Evidence/SARIF inputs; never written to adk-report.json.
	TargetName      string            `json:"-"`
	GitDirty        string            `json:"-"`
	RepoPrefix      string            `json:"-"`
	Data            DataVersions      `json:"-"`
	Components      []Component       `json:"-"`
	IgnoredFindings []finding.Finding `json:"-"`
	ScanRoot        string            `json:"-"`
	PrivatePaths    []string          `json:"-"`
	Untrusted       bool              `json:"-"`
	// NoIgnoreAdvice leaves out the .adkignore hint: the command does not read that file.
	NoIgnoreAdvice bool `json:"-"`
}

// AssetRow is one name in an assets report.
type AssetRow struct {
	Name        string    `json:"name"`
	Wildcard    bool      `json:"wildcard"` // seen only in "*." certificates
	CertCount   int       `json:"cert_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastExpiry  time.Time `json:"last_expiry"`
	StillValid  bool      `json:"still_valid"`
	Fingerprint string    `json:"fingerprint"`
}

func (r Report) isAssets() bool { return r.Kind == KindAssets }
