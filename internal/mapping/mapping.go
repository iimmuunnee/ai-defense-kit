// Package mapping loads Korean regulation mapping data (mappings/**/*.yaml)
// and attaches it to findings.
package mapping

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Review statuses.
const (
	StatusDraft   = "draft"
	StatusChecked = "checked"
	StatusExpert  = "expert"
)

// BuiltinKinds are the finding kinds that kinds.yaml may reference.
var BuiltinKinds = []string{"secret-current", "secret-history", "vuln-lib", "kev-lib", "malicious-lib", "SB-001", "AS-001", "AS-002", "AR-001", "AR-002", "AR-003", "AR-004", "AR-005", "AR-006", "CI-001", "CI-002", "CI-003", "CI-004", "CI-005", "WA-001", "WA-002", "WA-003", "WA-004", "WA-005", "WA-006", "WA-007", "WA-101", "WA-102", "WA-103", "DV-001", "DV-002", "DV-003", "DV-004", "DV-101", "DV-102", "DV-103", "DV-201", "DV-202", "DV-203", "DV-204"}

const (
	rootDir   = "mappings"
	kindsFile = "mappings/kinds.yaml"
)

// Review is the human/AI review record of an item.
type Review struct {
	Status    string `yaml:"status"`
	CheckedBy string `yaml:"checked_by"`
	CheckedAt string `yaml:"checked_at"`
	Quote     string `yaml:"quote"`
}

// Item is one regulation clause.
type Item struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	Clause        string `yaml:"clause"`
	SourceURL     string `yaml:"source_url"`
	SourceVersion string `yaml:"source_version"`
	SummaryKo     string `yaml:"summary_ko"`
	Review        Review `yaml:"review"`
}

// Catalog holds loaded items and the kind -> item ID table.
type Catalog struct {
	items map[string]Item
	kinds map[string][]string
}

func decodeStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

func validate(it Item, file string) error {
	base := strings.TrimSuffix(path.Base(file), ".yaml")
	switch {
	case it.ID == "":
		return fmt.Errorf("%s: id가 비어 있음", file)
	case it.ID != base:
		return fmt.Errorf("%s: 파일 이름이 id(%s)와 다름", file, it.ID)
	case it.Name == "":
		return fmt.Errorf("%s: name이 비어 있음", file)
	case !strings.HasPrefix(it.SourceURL, "https://"):
		return fmt.Errorf("%s: source_url은 https://로 시작해야 함", file)
	}
	switch it.Review.Status {
	case StatusDraft:
	case StatusChecked, StatusExpert:
		if it.Review.CheckedBy == "" {
			return fmt.Errorf("%s: %s 항목은 review.checked_by가 필요함", file, it.Review.Status)
		}
		if it.Review.CheckedAt == "" {
			return fmt.Errorf("%s: %s 항목은 review.checked_at이 필요함", file, it.Review.Status)
		}
		if _, err := time.Parse("2006-01-02", it.Review.CheckedAt); err != nil {
			return fmt.Errorf("%s: review.checked_at은 YYYY-MM-DD 형식이어야 함: %q", file, it.Review.CheckedAt)
		}
		if it.SourceVersion == "" {
			return fmt.Errorf("%s: %s 항목은 source_version이 필요함", file, it.Review.Status)
		}
	default:
		return fmt.Errorf("%s: 알 수 없는 review.status: %q (draft, checked, expert 중 하나)", file, it.Review.Status)
	}
	return nil
}

// Load reads mappings/**/*.yaml from fsys. A missing mappings directory
// yields an empty catalog.
func Load(fsys fs.FS) (Catalog, error) {
	c := Catalog{items: map[string]Item{}, kinds: map[string][]string{}}
	files := map[string]string{} // id -> file
	err := fs.WalkDir(fsys, rootDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path.Ext(p) != ".yaml" || p == kindsFile {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("%s: 읽을 수 없음: %v", p, err)
		}
		var it Item
		if err := decodeStrict(data, &it); err != nil {
			return fmt.Errorf("%s: 해석할 수 없음: %v", p, err)
		}
		if err := validate(it, p); err != nil {
			return err
		}
		if prev, dup := files[it.ID]; dup {
			return fmt.Errorf("%s: id %s가 %s와 중복됨", p, it.ID, prev)
		}
		files[it.ID] = p
		c.items[it.ID] = it
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Catalog{items: map[string]Item{}, kinds: map[string][]string{}}, nil
		}
		return Catalog{}, err
	}
	data, err := fs.ReadFile(fsys, kindsFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return c, nil
		}
		return Catalog{}, fmt.Errorf("%s: 읽을 수 없음: %v", kindsFile, err)
	}
	var kinds map[string][]string
	if err := yaml.Unmarshal(data, &kinds); err != nil {
		return Catalog{}, fmt.Errorf("%s: 해석할 수 없음: %v", kindsFile, err)
	}
	builtin := map[string]bool{}
	for _, k := range BuiltinKinds {
		builtin[k] = true
	}
	for kind, ids := range kinds {
		if !builtin[kind] {
			return Catalog{}, fmt.Errorf("%s: 알 수 없는 종류: %q", kindsFile, kind)
		}
		for _, id := range ids {
			if id == "" {
				return Catalog{}, fmt.Errorf("%s: %s 목록에 빈 ID가 있음", kindsFile, kind)
			}
			if _, ok := c.items[id]; !ok {
				return Catalog{}, fmt.Errorf("%s: %s가 가리키는 ID가 없음: %s", kindsFile, kind, id)
			}
		}
	}
	c.kinds = kinds
	if c.kinds == nil {
		c.kinds = map[string][]string{}
	}
	return c, nil
}

// Item returns the catalog item with the given ID.
func (c Catalog) Item(id string) (Item, bool) {
	it, ok := c.items[id]
	return it, ok
}

// Len is the number of items.
func (c Catalog) Len() int { return len(c.items) }

// Attach replaces each finding's Mappings with the resolved, deduped,
// ID-sorted list (finding's own IDs plus those from kinds.yaml). It returns
// one warning per unknown ID.
func (c Catalog) Attach(fs []finding.Finding) []string {
	var warnings []string
	warned := map[string]bool{}
	for i := range fs {
		seen := map[string]bool{}
		var ids []string
		add := func(id string) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		for _, m := range fs[i].Mappings {
			add(m.ID)
		}
		for _, id := range c.kinds[fs[i].Kind] {
			add(id)
		}
		sort.Strings(ids)
		var out []finding.Mapping
		for _, id := range ids {
			it, ok := c.items[id]
			if !ok {
				if !warned[id] {
					warned[id] = true
					warnings = append(warnings, fmt.Sprintf("국내 기준 정보가 없는 ID: %s (결과: %s)", id, fs[i].ID))
				}
				out = append(out, finding.Mapping{ID: id, ReviewStatus: StatusDraft})
				continue
			}
			status := it.Review.Status
			if status == "" {
				status = StatusDraft
			}
			m := finding.Mapping{ID: id, Name: it.Name, Clause: it.Clause, ReviewStatus: status, SourceURL: it.SourceURL}
			if status != StatusDraft {
				m.CheckedBy, m.CheckedAt = it.Review.CheckedBy, it.Review.CheckedAt
			}
			out = append(out, m)
		}
		fs[i].Mappings = out
	}
	return warnings
}

// Items returns a copy of all items, sorted by ID.
func (c Catalog) Items() []Item {
	out := make([]Item, 0, len(c.items))
	for _, it := range c.items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
