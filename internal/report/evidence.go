package report

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// EvidenceNotice is written into every evidence file.
const EvidenceNotice = "이 파일은 점검 기록입니다. 해시는 파일이 바뀌었는지 확인하는 용도이며 위변조를 막지 않습니다. 기준 충족을 증명하지 않으며 법률 자문이 아닙니다."

// EvidenceFile is the file name of the evidence file.
const EvidenceFile = "adk-evidence.json"

// ReportFile is one report written in this run, by file name and content hash.
type ReportFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type evidenceTool struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	Components []Component `json:"components"`
}

type evidenceGit struct {
	Commit string `json:"commit"`
	Dirty  string `json:"dirty"`
}

type evidenceCheck struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Error    string   `json:"error"`
	Warnings []string `json:"warnings"`
	Notes    []string `json:"notes,omitempty"`
}

type evidenceFinding struct {
	Fingerprint string           `json:"fingerprint"`
	ID          string           `json:"id"`
	Kind        string           `json:"kind"`
	Severity    finding.Severity `json:"severity"`
	Exploited   bool             `json:"exploited"`
	Location    string           `json:"location"`
	MappingIDs  []string         `json:"mapping_ids"`
}

type evidenceIgnored struct {
	Fingerprint string           `json:"fingerprint"`
	ID          string           `json:"id"`
	Severity    finding.Severity `json:"severity"`
	Location    string           `json:"location"`
}

type evidenceMappings struct {
	DataSet
	Items []MappingSource `json:"items"`
}

type evidenceData struct {
	Rules    *DataSet         `json:"rules"`
	Mappings evidenceMappings `json:"mappings"`
}

type evidenceExternal struct {
	Name      string     `json:"name"`
	Mode      string     `json:"mode"`
	Status    string     `json:"status"`
	FetchedAt *time.Time `json:"fetched_at"`
	Note      string     `json:"note,omitempty"`
}

type evidence struct {
	SchemaVersion int                `json:"schema_version"`
	Notice        string             `json:"notice"`
	Kind          string             `json:"kind"`
	Target        string             `json:"target"`
	Untrusted     bool               `json:"untrusted"`
	KnownList     string             `json:"known_list,omitempty"`
	ScannedAt     time.Time          `json:"scanned_at"`
	Tool          evidenceTool       `json:"tool"`
	Git           evidenceGit        `json:"git"`
	Data          evidenceData       `json:"data"`
	ExternalData  []evidenceExternal `json:"external_data"`
	Checks        []evidenceCheck    `json:"checks"`
	Findings      []evidenceFinding  `json:"findings"`
	Ignored       []evidenceIgnored  `json:"ignored"`
	Reports       []ReportFile       `json:"reports"`
	Signature     *struct{}          `json:"signature"`
}

// WriteEvidence writes the audit evidence for r as JSON indented by two
// spaces. It is built from a separate struct so finding evidence, explanations
// and fixes can never leak into it, and text from checks is scrubbed of
// absolute paths first.
func WriteEvidence(w io.Writer, r Report, files []ReportFile) error {
	scrub := func(s string) string { return Scrub(s, r.ScanRoot, r.PrivatePaths) }

	kind := r.Kind
	if kind == "" {
		kind = KindCode
	}
	target := r.Target
	if !r.isAssets() {
		target = r.TargetName
		if target == "" {
			target = TargetName(r.Target)
		}
	}
	dirty := r.GitDirty
	if dirty == "" {
		dirty = DirtyUnknown
	}

	ev := evidence{
		SchemaVersion: 1,
		Notice:        EvidenceNotice,
		Kind:          kind,
		Target:        target,
		Untrusted:     r.Untrusted,
		KnownList:     baseName(r.KnownList),
		ScannedAt:     r.ScannedAt,
		Tool:          evidenceTool{Name: "adk", Version: r.ToolVersion, Components: orEmpty(r.Components)},
		Git:           evidenceGit{Commit: r.GitCommit, Dirty: dirty},
		Data: evidenceData{
			Rules: r.Data.Rules,
			Mappings: evidenceMappings{
				DataSet: r.Data.Mappings.DataSet,
				Items:   orEmpty(r.Data.Mappings.Items),
			},
		},
		ExternalData: []evidenceExternal{},
		Checks:       []evidenceCheck{},
		Findings:     []evidenceFinding{},
		Ignored:      []evidenceIgnored{},
		Reports:      orEmpty(files),
	}

	for _, c := range r.Checks {
		ev.Checks = append(ev.Checks, evidenceCheck{
			Name: c.Name, Status: string(c.Status), Error: scrub(c.Error), Warnings: scrubAll(c.Warnings, scrub), Notes: scrubAll(c.Notes, scrub),
		})
		for _, x := range c.External {
			ev.ExternalData = append(ev.ExternalData, externalEntry(x, scrub))
		}
	}
	for _, f := range canonicalFindings(r.Findings) {
		ids := []string{}
		for _, m := range f.Mappings {
			ids = append(ids, m.ID)
		}
		ev.Findings = append(ev.Findings, evidenceFinding{
			Fingerprint: f.Fingerprint, ID: f.ID, Kind: f.Kind, Severity: f.Severity,
			Exploited: f.Exploited, Location: f.Location, MappingIDs: ids,
		})
	}
	for _, f := range canonicalFindings(r.IgnoredFindings) {
		ev.Ignored = append(ev.Ignored, evidenceIgnored{
			Fingerprint: f.Fingerprint, ID: f.ID, Severity: f.Severity, Location: f.Location,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(ev)
}

func externalEntry(x checker.ExternalData, scrub func(string) string) evidenceExternal {
	return evidenceExternal{Name: x.Name, Mode: x.Mode, Status: x.Status, FetchedAt: x.FetchedAt, Note: scrub(x.Note)}
}

func scrubAll(in []string, scrub func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, scrub(s))
	}
	return out
}

// baseName returns the last element of p for either slash style.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
