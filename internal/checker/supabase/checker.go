package supabase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	maxFileSize   = 1 << 20 // 1MB
	migrationsDir = "supabase/migrations"
	referenceURL  = "https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/database/postgres/row-level-security.mdx"
)

type supabaseChecker struct{ data fs.FS }

// New returns the Supabase checker. data supplies explain/SB-001.md and
// fixes/SB-001/sql.md.
func New(data fs.FS) checker.Checker { return supabaseChecker{data: data} }

func (supabaseChecker) Name() string { return "supabase" }

func (c supabaseChecker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	var res checker.Result
	dir := filepath.Join(t.Root, filepath.FromSlash(migrationsDir))
	entries, err := os.ReadDir(dir) // sorted by file name
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, nil
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s 폴더를 읽지 못했습니다: %v", migrationsDir, err))
		return res, nil
	}

	var files []SQLFile
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return checker.Result{}, err
		}
		if !e.Type().IsRegular() || !strings.EqualFold(filepath.Ext(e.Name()), ".sql") {
			continue
		}
		rel := path.Join(migrationsDir, e.Name())
		content, err := readCapped(filepath.Join(dir, e.Name()))
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s을(를) 읽지 못해 건너뛰었습니다: %v", rel, err))
			continue
		}
		files = append(files, SQLFile{Path: rel, Content: content})
	}
	if err := ctx.Err(); err != nil {
		return checker.Result{}, err
	}

	tables, warns := Analyze(files)
	res.Warnings = append(res.Warnings, warns...)
	explain, fix := c.read("explain/SB-001.md"), c.read("fixes/SB-001/sql.md")
	for _, tb := range tables {
		// The table name is scanned on its own (value rule) before it goes into
		// the title; the fingerprint keeps the name as written.
		ev := "public." + finding.ScrubValueText(tb.Name)
		res.Findings = append(res.Findings, finding.Finding{
			ID:          "SB-001",
			Source:      "supabase",
			Kind:        "SB-001",
			Severity:    finding.High,
			Confidence:  finding.Suspect, // RLS may have been enabled in the dashboard
			Location:    tb.File,
			Line:        tb.Line,
			Evidence:    ev,
			Title:       "RLS가 켜지지 않은 테이블: " + ev,
			ExplainKo:   explain,
			Fix:         fix,
			References:  []string{referenceURL},
			Fingerprint: finding.MakeFingerprint("SB-001", tb.File, "public."+tb.Name),
		})
	}
	return res, nil
}

func (c supabaseChecker) read(name string) string {
	if c.data == nil {
		return ""
	}
	b, err := fs.ReadFile(c.data, name)
	if err != nil {
		return ""
	}
	return string(b)
}

func readCapped(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxFileSize {
		return "", fmt.Errorf("파일이 1MB보다 큽니다")
	}
	return string(b), nil
}
