// Package assets는 인증서 공개 기록에서 찾은 이름을 서브도메인으로 정리하고,
// 운영자가 아는 목록과 비교한다. 네트워크에는 접속하지 않는다.
package assets

import (
	"sort"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/assets/ctlog"
)

// Asset은 이름 하나로 합친 결과다.
type Asset struct {
	Name string
	// Wildcard는 이 이름을 "*."로만 본 적이 있다는 뜻이다.
	Wildcard   bool
	CertCount  int
	FirstSeen  time.Time
	LastExpiry time.Time
	// StillValid는 지금 시각이 어느 인증서의 NotBefore~NotAfter 안에 있다는 뜻이다.
	StillValid bool
}

// ValidHostname은 s가 소문자 호스트 이름 문법에 맞는지 돌려준다 (규칙은 validHostname).
func ValidHostname(s string) bool { return validHostname(s) }

// validHostname은 호스트 이름 문법을 검사한다.
// 라벨은 영문자, 숫자, '-' (1~63자, '-'로 시작하거나 끝나지 않음), 전체 253자 이하.
// 밑줄이 든 이름(_dmarc 등)은 호스트 이름이 아니므로 거부한다.
// 국제화 도메인은 xn-- 형태 그대로 다룬다.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
			if !ok {
				return false
			}
		}
	}
	return true
}

// Collect는 crt.sh 항목에서 domain 아래의 이름을 정리해 이름 순으로 돌려준다.
// domain은 정리된 값(소문자, 끝 점 없음)이어야 하지만 방어적으로 한 번 더 정리한다.
func Collect(domain string, entries []ctlog.Entry, now time.Time) []Asset {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	byName := map[string]*Asset{}
	for _, e := range entries {
		seen := map[string]bool{} // 한 인증서 안에서 같은 이름은 한 번만 센다
		seenPlain := map[string]bool{}
		for _, raw := range strings.Split(e.NameValue, "\n") {
			n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
			wild := false
			if strings.HasPrefix(n, "*.") {
				n = n[2:]
				wild = true
			}
			if domain == "" || (n != domain && !strings.HasSuffix(n, "."+domain)) {
				continue
			}
			if !validHostname(n) {
				continue
			}
			if !wild {
				seenPlain[n] = true
			}
			if seen[n] {
				continue
			}
			seen[n] = true
			a := byName[n]
			if a == nil {
				a = &Asset{Name: n, Wildcard: true}
				byName[n] = a
			}
			a.CertCount++
			if !e.NotBefore.IsZero() && (a.FirstSeen.IsZero() || e.NotBefore.Before(a.FirstSeen)) {
				a.FirstSeen = e.NotBefore
			}
			if e.NotAfter.After(a.LastExpiry) {
				a.LastExpiry = e.NotAfter
			}
			if !e.NotBefore.IsZero() && !e.NotAfter.IsZero() &&
				!now.Before(e.NotBefore) && !now.After(e.NotAfter) {
				a.StillValid = true
			}
		}
		for n := range seenPlain {
			byName[n].Wildcard = false
		}
	}
	out := make([]Asset, 0, len(byName))
	for _, a := range byName {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
