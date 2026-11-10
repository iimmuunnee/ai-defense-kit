// Package ctlog는 crt.sh(인증서 투명성 공개 기록)를 조회한다.
// 대상 사이트에는 접속하지 않고, crt.sh에만 질의한다.
package ctlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBaseURL  = "https://crt.sh/"
	defaultAttempts = 3
	defaultUA       = "adk"
	truncatedAt     = 10000 // crt.sh가 한 번에 돌려주는 행 한도 (근거 자료 3-1)
)

// requestTimeout은 요청 한 번의 시간 제한이다. 테스트에서만 바꾼다.
var requestTimeout = 60 * time.Second

// maxBodyBytes는 응답 본문 읽기 한도(64MB)다. 테스트에서만 바꾼다.
var maxBodyBytes int64 = 64 << 20

// Entry는 crt.sh 응답의 한 행이다.
type Entry struct {
	NameValue   string
	NotBefore   time.Time
	NotAfter    time.Time
	ResultCount int
	ID          int64
}

// Options는 조회 설정이다. 0값이면 기본값을 쓴다.
type Options struct {
	BaseURL        string
	HTTPClient     *http.Client
	UserAgent      string
	ExcludeExpired bool
	Attempts       int
	// Backoff는 attempt번째(1부터) 시도가 실패한 뒤 기다릴 시간을 돌려준다.
	Backoff func(attempt int) time.Duration
}

type rawEntry struct {
	NameValue   string `json:"name_value"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	ResultCount int    `json:"result_count"`
	ID          int64  `json:"id"`
}

// redirectError는 허용하지 않는 리다이렉트다. 재시도하지 않는다.
type redirectError struct{ host string }

func (e *redirectError) Error() string {
	return fmt.Sprintf("허용되지 않는 리다이렉트입니다 (대상 호스트: %s)", e.host)
}

// checkRedirect는 같은 호스트의 http에서 https 이동만 허용한다.
// 나가는 요청이 crt.sh 하나뿐이어야 하기 때문이다.
func checkRedirect(req *http.Request, via []*http.Request) error {
	prev := via[len(via)-1]
	if len(via) == 1 && prev.URL.Scheme == "http" && req.URL.Scheme == "https" &&
		strings.EqualFold(prev.URL.Hostname(), req.URL.Hostname()) {
		return nil
	}
	return &redirectError{host: req.URL.Host}
}

// retryable은 다시 시도해 볼 만한 오류다.
type retryable struct{ err error }

func (e *retryable) Error() string { return e.err.Error() }
func (e *retryable) Unwrap() error { return e.err }

func defaultBackoff(attempt int) time.Duration {
	return time.Duration(1<<attempt) * time.Second // 1회 실패 후 2초, 2회 실패 후 4초
}

// Fetch는 domain이 들어간 인증서 기록을 조회한다.
func Fetch(ctx context.Context, domain string, opt Options) ([]Entry, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("crt.sh 조회에 실패했습니다: 도메인이 비어 있습니다")
	}
	if strings.Contains(domain, "%") {
		return nil, errors.New("crt.sh 조회에 실패했습니다: 도메인에 %를 쓸 수 없습니다")
	}
	base := opt.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("crt.sh 조회에 실패했습니다: 주소가 올바르지 않습니다: %w", err)
	}
	q := url.Values{}
	q.Set("dNSName", domain) // 파라미터 이름은 대소문자를 가린다: 소문자 dnsname은 404/502 (근거 자료 6절)
	q.Set("match", "ILIKE")
	q.Set("deduplicate", "Y")
	q.Set("output", "json")
	if opt.ExcludeExpired {
		q.Set("exclude", "expired")
	}
	u.RawQuery = q.Encode()

	// 넘겨받은 클라이언트는 건드리지 않고 얕게 복사해 리다이렉트 정책만 건다.
	var c http.Client
	if opt.HTTPClient != nil {
		c = *opt.HTTPClient
	}
	c.CheckRedirect = checkRedirect
	client := &c
	ua := opt.UserAgent
	if ua == "" {
		ua = defaultUA
	}
	attempts := opt.Attempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	backoff := opt.Backoff
	if backoff == nil {
		backoff = defaultBackoff
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		entries, err := fetchOnce(ctx, client, u.String(), ua)
		if err == nil {
			return entries, nil
		}
		lastErr = err
		var r *retryable
		if !errors.As(err, &r) || ctx.Err() != nil || attempt == attempts {
			break
		}
		if d := backoff(attempt); d > 0 {
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, fmt.Errorf("crt.sh 조회에 실패했습니다: %w", ctx.Err())
			case <-t.C:
			}
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("crt.sh 조회에 실패했습니다: %w", ctx.Err())
	}
	return nil, fmt.Errorf("crt.sh 조회에 실패했습니다: %w", lastErr)
}

func fetchOnce(ctx context.Context, client *http.Client, target, ua string) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		var re *redirectError
		if errors.As(err, &re) {
			return nil, re
		}
		return nil, &retryable{fmt.Errorf("연결 오류: %w", err)}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, &retryable{fmt.Errorf("서버가 오류를 돌려줬습니다 (HTTP %d)", resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("요청이 거절됐습니다 (HTTP %d)", resp.StatusCode)
	}
	if !isJSON(resp.Header.Get("Content-Type")) {
		ct := resp.Header.Get("Content-Type")
		msg := "crt.sh가 JSON 대신 오류 페이지를 돌려줬습니다"
		if mt, _, _ := mime.ParseMediaType(ct); mt != "text/html" {
			if ct == "" {
				ct = "없음"
			}
			msg += " (Content-Type: " + ct + ")"
		}
		return nil, &retryable{errors.New(msg)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, &retryable{fmt.Errorf("응답을 읽다가 끊겼습니다: %w", err)}
	}
	if int64(len(body)) > maxBodyBytes {
		return nil, fmt.Errorf("응답 크기가 한도(%dMB)를 넘었습니다", maxBodyBytes>>20)
	}
	var raws []rawEntry
	if err := json.Unmarshal(body, &raws); err != nil {
		return nil, fmt.Errorf("응답이 올바른 JSON 배열이 아닙니다: %w", err)
	}
	if raws == nil { // JSON null
		return nil, errors.New("응답이 올바른 JSON 배열이 아닙니다: null")
	}
	out := make([]Entry, 0, len(raws))
	for _, r := range raws {
		out = append(out, Entry{
			NameValue:   r.NameValue,
			NotBefore:   parseTime(r.NotBefore),
			NotAfter:    parseTime(r.NotAfter),
			ResultCount: r.ResultCount,
			ID:          r.ID,
		})
	}
	return out, nil
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

var timeLayouts = []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"}

// parseTime은 알려진 형식을 차례로 시도하고, 모두 실패하면 0값을 돌려준다.
func parseTime(s string) time.Time {
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Truncated는 ResultCount 합이 10000 이상이면 참이다. crt.sh의 JSON 응답에는
// 잘림 표시가 없어서, 한도에 닿았을 가능성을 이 합으로 추정한다.
func Truncated(entries []Entry) bool {
	sum := 0
	for _, e := range entries {
		sum += e.ResultCount
	}
	return sum >= truncatedAt
}
