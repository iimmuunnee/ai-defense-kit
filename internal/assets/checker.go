package assets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/assets/ctlog"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	// CheckerName은 점검기 이름이자 결과의 Source다.
	CheckerName = "assets"

	idUnknown = "AS-001" // 알려진 목록에 없는 이름
	idFound   = "AS-002" // 알려진 목록 없이 찾은 이름

	// TruncatedWarning은 crt.sh 결과가 한도에 닿았을 수 있을 때의 경고다.
	TruncatedWarning = "crt.sh 결과가 10000행 한도에 닿아 일부만 받았을 수 있습니다. --exclude-expired로 다시 확인해 보세요."

	// TruncatedWarningExcludeExpired는 --exclude-expired를 이미 쓴 경우의 경고다.
	TruncatedWarningExcludeExpired = "crt.sh 결과가 10000행 한도에 닿아 일부만 받았을 수 있습니다. 하위 도메인별로 나눠 조회해 보세요."
)

// Checker는 인증서 공개 기록(crt.sh)에서 Target.Domain 아래의 이름을 찾는다.
// crt.sh에만 질의하고, 찾은 이름에는 접속하지 않는다.
type Checker struct {
	data  fs.FS
	opt   ctlog.Options
	known *Known
	now   func() time.Time

	mu   sync.Mutex
	last []Asset
}

// NewChecker는 자산 점검기를 만든다. data는 explain/AS-001.md, explain/AS-002.md를 준다.
// known이 nil이면 찾은 이름을 모두 AS-002로, 아니면 목록에 없는 이름만 AS-001로 낸다.
// now가 nil이면 time.Now를 쓴다.
func NewChecker(data fs.FS, opt ctlog.Options, known *Known, now func() time.Time) *Checker {
	if now == nil {
		now = time.Now
	}
	return &Checker{data: data, opt: opt, known: known, now: now}
}

// Name은 점검기 이름이다.
func (c *Checker) Name() string { return CheckerName }

// Run은 crt.sh를 조회해 결과를 만든다. 조회에 실패하면 오류를 돌려준다
// ("찾은 것이 없음"으로 보이면 안 되기 때문이다).
func (c *Checker) Run(ctx context.Context, t checker.Target) (checker.Result, error) {
	ext := checker.ExternalData{Name: "crt.sh", Mode: checker.ModeOnline, Status: checker.ExternalSkipped}
	if t.Domain == "" {
		return checker.Result{External: []checker.ExternalData{ext}}, errors.New("점검할 도메인이 없습니다")
	}
	entries, err := ctlog.Fetch(ctx, t.Domain, c.opt)
	if err != nil {
		ext.Status = checker.ExternalFailed
		return checker.Result{External: []checker.ExternalData{ext}}, err
	}
	now := c.now()
	ext.Status, ext.FetchedAt = checker.ExternalUsed, &now
	as := Collect(t.Domain, entries, now)

	id, titlePrefix := idFound, "인증서 공개 기록에서 찾은 서브도메인: "
	if c.known != nil {
		as = Unknown(as, *c.known)
		id, titlePrefix = idUnknown, "목록에 없는 서브도메인: "
	}
	explain := c.read("explain/" + id + ".md")

	res := checker.Result{External: []checker.ExternalData{ext}}
	for _, a := range as {
		res.Findings = append(res.Findings, finding.Finding{
			ID:          id,
			Source:      CheckerName,
			Kind:        id,
			Severity:    finding.Info,
			Confidence:  finding.Suspect, // 소유를 확인하지 않았다
			Location:    a.Name,
			Evidence:    evidence(a),
			Title:       titlePrefix + finding.ScrubValueText(a.Name), // the host name is scanned on its own
			ExplainKo:   explain,
			Fingerprint: finding.MakeFingerprint(id, a.Name, a.Name),
		})
	}
	if ctlog.Truncated(entries) {
		w := TruncatedWarning
		if c.opt.ExcludeExpired {
			w = TruncatedWarningExcludeExpired
		}
		res.Warnings = append(res.Warnings, w)
	}

	c.mu.Lock()
	c.last = as
	c.mu.Unlock()
	return res, nil
}

// Assets는 마지막으로 성공한 Run의 결과와 같은 이름들의 자세한 값을 돌려준다.
// 리포트 표(인증서 수, 마지막 만료, 와일드카드 여부)를 만들 때 쓴다.
func (c *Checker) Assets() []Asset {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Asset(nil), c.last...)
}

func evidence(a Asset) string {
	state := "지금 유효한 인증서 없음"
	if a.StillValid {
		state = "지금 유효함"
	}
	return fmt.Sprintf("인증서 %d개, 처음 발급 %s, 마지막 만료 %s, %s (소유 미확인)",
		a.CertCount, day(a.FirstSeen), day(a.LastExpiry), state)
}

// day는 날짜를 UTC 기준 YYYY-MM-DD로 쓴다. 0값이면 "알 수 없음"이다.
func day(t time.Time) string {
	if t.IsZero() {
		return "알 수 없음"
	}
	return t.UTC().Format("2006-01-02")
}

func (c *Checker) read(name string) string {
	if c.data == nil {
		return ""
	}
	b, err := fs.ReadFile(c.data, name)
	if err != nil {
		return ""
	}
	return string(b)
}
