package deps

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/kev"
)

// 리포트가 라이브러리@버전 단위로 묶을 수 있도록 결과마다 그 값을 남긴다.
func TestDepsFindingsCarryPackage(t *testing.T) {
	root := t.TempDir()
	res, err := newChecker(t, root, nil, nil).Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) == 0 {
		t.Fatalf("err=%v findings=%d", err, len(res.Findings))
	}
	for _, f := range res.Findings {
		if !strings.Contains(f.Package, "@") || !strings.HasPrefix(f.Evidence, f.Package+" ") {
			t.Errorf("%s: package %q, evidence %q", f.ID, f.Package, f.Evidence)
		}
	}
}

// runAt reports the sample results as if they came from lockfile rel.
func runAt(t *testing.T, rel string) []finding.Finding {
	t.Helper()
	root := t.TempDir()
	c := New(testFS, Options{
		Scan: func(osvscanner.ScannerActions) (models.VulnerabilityResults, error) {
			r := loadResults(t, root)
			for i := range r.Results {
				r.Results[i].Source.Path = filepath.Join(root, filepath.FromSlash(rel))
			}
			return r, nil
		},
		FetchKEV: func(context.Context) (*kev.Catalog, error) { return loadKEV(t), nil },
	})
	res, err := c.Run(context.Background(), checker.Target{Root: root})
	if err != nil || len(res.Findings) == 0 {
		t.Fatalf("%s: err=%v findings=%d", rel, err, len(res.Findings))
	}
	return res.Findings
}

// 문서 사이트, 예제, 시험 자료 폴더의 잠금 파일은 앱 본체가 아닐 수 있어 "의심"으로 낮춘다.
// 지우지는 않는다. 등급도 그대로다.
func TestDepsDocsAndExampleLockfilesAreSuspect(t *testing.T) {
	for _, rel := range []string{
		"docs/package-lock.json",
		"dev-docs/yarn.lock",
		"examples/with-nextjs/yarn.lock",
		"packages/app/example/package-lock.json",
		"testdata/go.mod",
		"test/fixtures/package-lock.json",
	} {
		for _, f := range runAt(t, rel) {
			if f.Confidence != finding.Suspect {
				t.Errorf("%s %s: confidence %s, want suspect", rel, f.ID, f.Confidence)
			}
		}
	}
	for _, rel := range []string{"package-lock.json", "apps/web/package-lock.json", "documentation-site-builder/package-lock.json"} {
		for _, f := range runAt(t, rel) {
			if f.Confidence != finding.Certain {
				t.Errorf("%s %s: confidence %s, want certain", rel, f.ID, f.Confidence)
			}
		}
	}
}
