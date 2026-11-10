package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
)

// mappingData describes the mapping data set: content hash, count and the
// source version and review state of every item. An empty review status is
// recorded as "draft", the same default the reports show.
func mappingData(data fs.FS, origin string, cat mapping.Catalog) (report.MappingData, error) {
	sum, err := report.HashTree(data, "mappings")
	if err != nil {
		return report.MappingData{}, fmt.Errorf("국내 기준 데이터 해시를 구하지 못했습니다: %w", err)
	}
	md := report.MappingData{
		DataSet: report.DataSet{Origin: origin, SHA256: sum, Count: cat.Len()},
		Items:   []report.MappingSource{},
	}
	for _, it := range cat.Items() {
		status := it.Review.Status
		if status == "" {
			status = "draft"
		}
		md.Items = append(md.Items, report.MappingSource{ID: it.ID, SourceVersion: it.SourceVersion, ReviewStatus: status})
	}
	return md, nil
}

// ruleData describes the rule data set. ruleCount is the number of loaded rules.
func ruleData(data fs.FS, origin string, ruleCount int) (*report.DataSet, error) {
	sum, err := report.HashTree(data, "rules")
	if err != nil {
		return nil, fmt.Errorf("규칙 데이터 해시를 구하지 못했습니다: %w", err)
	}
	return &report.DataSet{Origin: origin, SHA256: sum, Count: ruleCount}, nil
}

// scanPrivatePaths lists absolute paths a scan was given that must not appear
// in evidence output: the folder as typed (only its absolute form, and only
// when it differs from the resolved root) and the optional file and folder
// flags. It never holds a relative string: a short relative name such as "api"
// would also match inside file names and rule titles.
func scanPrivatePaths(root, typed string, extra ...string) []string {
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil || abs == root || slices.Contains(out, abs) {
			return
		}
		out = append(out, abs)
	}
	add(typed)
	for _, p := range extra {
		add(p)
	}
	return out
}

// hashFile returns the SHA-256 of the bytes on disk.
func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
