package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

const (
	webhookEnv     = "ADK_WATCH_WEBHOOK"
	webhookTimeout = 5 * time.Second
	scrubbed       = "[가림]"
)

// scrubber removes RPC and webhook addresses (and the parts of them that
// can hold a key) from text. The RPC client already keeps addresses out of
// its errors; this is a second net for everything that reaches the terminal,
// a report or a webhook.
type scrubber struct{ words []string }

func newScrubber(raws ...string) *scrubber {
	seen := map[string]bool{}
	var words []string
	add := func(w string, min int) {
		if len(w) >= min && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}
	for _, raw := range raws {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		add(raw, 1)
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		add(u.Host, 4)
		add(u.Hostname(), 4)
		if u.User != nil {
			add(u.User.Username(), 4)
			if pw, ok := u.User.Password(); ok {
				add(pw, 4)
			}
		}
		add(strings.Trim(u.Path, "/"), 6)
		for _, seg := range strings.Split(u.Path, "/") {
			add(seg, 6)
		}
		add(u.RawQuery, 4)
		for _, vs := range u.Query() {
			for _, v := range vs {
				add(v, 4)
			}
		}
		add(u.Fragment, 4)
	}
	sort.Slice(words, func(i, j int) bool { return len(words[i]) > len(words[j]) })
	return &scrubber{words: words}
}

func (s *scrubber) clean(in string) string {
	for _, w := range s.words {
		in = strings.ReplaceAll(in, w, scrubbed)
	}
	return in
}

// scrubbedError is an error whose text is cleaned and which still unwraps
// to the original, so errors.Is keeps working.
type scrubbedError struct {
	msg string
	err error
}

func (e scrubbedError) Error() string { return e.msg }
func (e scrubbedError) Unwrap() error { return e.err }

func (s *scrubber) err(err error) error {
	return scrubbedError{msg: s.clean(err.Error()), err: err}
}

type hookFinding struct {
	Key      string `json:"key"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Confidence is "suspect" when the value came from a node that looks stopped
	// or from an exported file older than max_age.
	Confidence string `json:"confidence"`
}

// hookPayload is the whole webhook body: keys, ids, severities and confidences only. It
// holds no value read from a target, no RPC address and no secret.
type hookPayload struct {
	Tool       string        `json:"tool"`
	Findings   []hookFinding `json:"findings"`
	Unverified []string      `json:"unverified"`
	// StaleTargets are the keys read from a node that looks stopped or from an
	// exported file older than max_age: a finding
	// on them may not be a real change.
	StaleTargets   []string `json:"stale_targets"`
	NewTargets     []string `json:"new_targets"`
	RemovedTargets []string `json:"removed_targets"`
	// BaselineError: the baseline could not be used, so nothing was compared.
	BaselineError bool `json:"baseline_error"`
}

func buildPayload(o watch.Outcome, fs []finding.Finding, baselineBad bool) hookPayload {
	p := hookPayload{BaselineError: baselineBad, Tool: "adk watch", Findings: []hookFinding{}, Unverified: []string{}, StaleTargets: append([]string{}, o.Stale...),
		NewTargets: append([]string{}, o.NewTargets...), RemovedTargets: append([]string{}, o.RemovedTargets...)}
	for _, f := range fs {
		p.Findings = append(p.Findings, hookFinding{Key: f.Location, ID: f.ID, Severity: f.Severity.String(), Confidence: string(f.Confidence)})
	}
	for k := range o.Unverified {
		p.Unverified = append(p.Unverified, k)
	}
	sort.Strings(p.Unverified)
	return p
}

// worthSending is true when a one-shot check found something or could not
// verify something. Under --every every state change is sent instead.
func worthSending(o watch.Outcome, fs []finding.Finding, baselineBad bool) bool {
	if baselineBad {
		return true
	}
	for _, f := range fs {
		if f.Severity != finding.Info {
			return true
		}
	}
	return len(o.Unverified) > 0 || len(o.NewTargets) > 0 || len(o.RemovedTargets) > 0
}

// webhookClient refuses redirects and, unless told otherwise, ignores a proxy
// set in the environment: the webhook address usually holds a secret.
func webhookClient(allowEnvProxy bool) *http.Client {
	return &http.Client{
		Timeout:       webhookTimeout,
		Transport:     rpc.Transport(allowEnvProxy),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// sendWebhook posts the payload to ADK_WATCH_WEBHOOK, if set, and reports
// whether there is nothing left to deliver: true when it was delivered or no
// webhook is set. A failure is a warning on stderr and never changes the exit
// code. No message contains the address.
func sendWebhook(ctx context.Context, ev evaluation, allowEnvProxy bool, stderr io.Writer) bool {
	raw := strings.TrimSpace(os.Getenv(webhookEnv))
	if raw == "" {
		return true
	}
	warn := func(why string) bool {
		fmt.Fprintf(stderr, "경고: 웹훅을 보내지 못했습니다 (%s). 종료 코드는 바뀌지 않습니다.\n", why)
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return warn(webhookEnv + " 값이 올바른 http(s) 주소가 아닙니다")
	}
	body, err := json.Marshal(buildPayload(ev.outcome, ev.findings, ev.baselineBad))
	if err != nil {
		return warn("본문을 만들지 못했습니다")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(body))
	if err != nil {
		return warn("요청을 만들지 못했습니다")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient(allowEnvProxy).Do(req)
	if err != nil {
		// The error text embeds the address: it is dropped.
		return warn("연결하지 못했습니다")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return warn(fmt.Sprintf("리디렉션 응답(HTTP %d)은 따르지 않습니다", resp.StatusCode))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return warn(fmt.Sprintf("HTTP 상태 %d", resp.StatusCode))
	}
	return true
}
