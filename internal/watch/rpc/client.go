// Package rpc is a minimal read-only JSON-RPC client. Calls in the EVM format
// go through Call and its variants; other formats (XRPL) use PostJSON and Agree.
//
// RPC URLs usually carry API keys, so no error returned from this package
// contains a URL or any part of one (host, path, query). Endpoints are named
// by position, for example "RPC 1".
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrDisagree means the configured endpoints returned different results,
// even after one retry.
var ErrDisagree = errors.New("RPC 응답이 서로 다릅니다")

const (
	maxBody        = 1 << 20 // 1MiB
	defaultTimeout = 15 * time.Second
)

// Client talks to one or more JSON-RPC endpoints.
type Client struct {
	urls []string
	hc   *http.Client
	err  error // when set, every call returns it
}

var (
	directTransport   = newTransport(nil)
	envProxyTransport = newTransport(http.ProxyFromEnvironment)
)

func newTransport(proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = proxy
	return t
}

// Transport returns the shared transport for connections to configured
// addresses. Those addresses usually hold an API key, and a proxy sees all of
// a plain http request, so a proxy from the environment is used only when
// allowEnvProxy says so.
func Transport(allowEnvProxy bool) *http.Transport {
	if allowEnvProxy {
		return envProxyTransport
	}
	return directTransport
}

// New returns a client for urls. Redirects are refused, on an injected
// client too (a shallow copy is used; c is not modified). A nil c gets a
// default client with a timeout that connects directly, ignoring any proxy
// set in the environment.
func New(urls []string, c *http.Client) *Client {
	var hc http.Client
	if c == nil {
		hc = http.Client{Timeout: defaultTimeout, Transport: Transport(false)}
	} else {
		hc = *c
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{urls: append([]string(nil), urls...), hc: &hc}
}

// NewWithEnvProxy is New with a nil client, except that it uses the proxy set
// in the environment.
func NewWithEnvProxy(urls []string) *Client {
	return New(urls, &http.Client{Timeout: defaultTimeout, Transport: Transport(true)})
}

// NewFailed returns a client whose every call returns err.
func NewFailed(err error) *Client {
	return &Client{err: err}
}

func label(i int) string { return fmt.Sprintf("RPC %d", i+1) }

// Call sends the request to the first URL.
func (c *Client) Call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	if c.err != nil {
		return nil, c.err
	}
	if len(c.urls) == 0 {
		return nil, errors.New("RPC 주소가 설정되지 않았습니다")
	}
	return c.callAt(ctx, 0, method, params, true)
}

// CallAll sends the request to every URL and returns the results in order. It
// fails if any URL fails. Each result must be a hex string.
func (c *Client) CallAll(ctx context.Context, method string, params []any) ([]json.RawMessage, error) {
	return strict(c.callAll(ctx, method, params, true))
}

// CallAllRaw is CallAll for methods whose result is not a hex string, such as
// a block. The caller checks the result. The size limit and the rule that no
// error holds a URL are the same.
func (c *Client) CallAllRaw(ctx context.Context, method string, params []any) ([]json.RawMessage, error) {
	return strict(c.callAll(ctx, method, params, false))
}

// CallEach is CallAll that does not stop at a failure: it returns one result
// and one error per URL, in order. errs[i] is nil when URL i answered. When no
// URL can be asked (none configured, or the client was built failed) it returns
// no results and one error.
func (c *Client) CallEach(ctx context.Context, method string, params []any) ([]json.RawMessage, []error) {
	return c.callAll(ctx, method, params, true)
}

// CallEachRaw is CallEach for methods whose result is not a hex string.
func (c *Client) CallEachRaw(ctx context.Context, method string, params []any) ([]json.RawMessage, []error) {
	return c.callAll(ctx, method, params, false)
}

func strict(res []json.RawMessage, errs []error) ([]json.RawMessage, error) {
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (c *Client) callAll(ctx context.Context, method string, params []any, hexOnly bool) ([]json.RawMessage, []error) {
	if c.err != nil {
		return nil, []error{c.err}
	}
	if len(c.urls) == 0 {
		return nil, []error{errors.New("RPC 주소가 설정되지 않았습니다")}
	}
	out := make([]json.RawMessage, len(c.urls))
	errs := make([]error, len(c.urls))
	for i := range c.urls {
		out[i], errs[i] = c.callAt(ctx, i, method, params, hexOnly)
	}
	return out, errs
}

// Partial says which endpoints did not answer a question that the others did.
// Missing holds their positions, counted from 1. It is empty when all answered.
type Partial struct{ Missing []int }

// Agreed asks every URL and returns the result if the URLs that answered agree
// (hex case ignored). On disagreement it asks again once after retryAfter; a
// second disagreement is an error wrapping ErrDisagree. There is no majority
// vote. A URL that did not answer is named in Partial; if none answers the
// first error is returned.
func (c *Client) Agreed(ctx context.Context, method string, params []any, retryAfter time.Duration) (json.RawMessage, Partial, error) {
	return Agree(ctx, retryAfter, method, func(ctx context.Context) ([]json.RawMessage, []error) {
		return c.CallEach(ctx, method, params)
	}, func(a, b json.RawMessage) bool { return strings.EqualFold(string(a), string(b)) })
}

// Agree runs ask, which returns one result and one error per endpoint, and
// returns the first answered result only if eq holds between it and every other
// answered one. An endpoint whose error is not nil did not answer; its position
// (from 1) is in Partial.Missing. If none answered, the first error is
// returned. On disagreement it asks again once after retryAfter; a second
// disagreement is an error wrapping ErrDisagree (what names the question in
// that error). There is no majority vote. The caller decides what is compared:
// results from servers that report different ledger positions are compared by
// the fields taken from them.
func Agree[T any](ctx context.Context, retryAfter time.Duration, what string, ask func(context.Context) ([]T, []error), eq func(a, b T) bool) (T, Partial, error) {
	var zero T
	// settle returns the answered values and who is missing, or an error when
	// nobody answered.
	settle := func() ([]T, Partial, error) {
		res, errs := ask(ctx)
		n := max(len(res), len(errs))
		if n == 0 {
			return nil, Partial{}, errors.New("RPC 주소가 설정되지 않았습니다")
		}
		var answered []T
		var p Partial
		var first error
		for i := 0; i < n; i++ {
			var err error
			if i < len(errs) {
				err = errs[i]
			}
			if err == nil && i >= len(res) {
				err = errors.New("RPC 주소가 설정되지 않았습니다")
			}
			if err != nil {
				if first == nil {
					first = err
				}
				p.Missing = append(p.Missing, i+1)
				continue
			}
			answered = append(answered, res[i])
		}
		if len(answered) == 0 {
			return nil, Partial{}, first
		}
		if first != nil && ctx.Err() != nil {
			// The rest did not answer because the time ran out, not because
			// they are down.
			return nil, Partial{}, first
		}
		return answered, p, nil
	}
	agreed := func(vs []T) bool {
		for _, v := range vs[1:] {
			if !eq(v, vs[0]) {
				return false
			}
		}
		return true
	}
	vs, p, err := settle()
	if err != nil {
		return zero, Partial{}, err
	}
	if agreed(vs) {
		return vs[0], p, nil
	}
	if retryAfter > 0 {
		t := time.NewTimer(retryAfter)
		select {
		case <-ctx.Done():
			t.Stop()
			return zero, Partial{}, ctx.Err()
		case <-t.C:
		}
	}
	vs, p, err = settle()
	if err != nil {
		return zero, Partial{}, err
	}
	if agreed(vs) {
		return vs[0], p, nil
	}
	return zero, Partial{}, fmt.Errorf("%w: %s 요청에서 RPC %d개의 결과가 일치하지 않습니다", ErrDisagree, what, len(vs))
}

// Len returns the number of configured URLs.
func (c *Client) Len() int { return len(c.urls) }

type response struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error"`
}

func (c *Client) callAt(ctx context.Context, i int, method string, params []any, hexOnly bool) (json.RawMessage, error) {
	name := label(i)
	if params == nil {
		params = []any{}
	}
	data, err := c.PostJSON(ctx, i, map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s: JSON 응답이 아닙니다", name)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("%s: JSON-RPC 오류 (코드 %d)", name, r.Error.Code)
	}
	if hexOnly && !validHexResult(r.Result) {
		return nil, fmt.Errorf("%s: 결과가 16진수 문자열이 아닙니다", name)
	}
	return r.Result, nil
}

// PostJSON sends v as a JSON body to the URL at position i and returns the
// body of a 200 answer. It is the transport under every call: redirects are
// refused, the answer is limited to 1MiB, and no error holds a URL or any part
// of one (the endpoint is named by position). What the body means, and whether
// it is JSON at all, is up to the caller.
func (c *Client) PostJSON(ctx context.Context, i int, v any) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	if i < 0 || i >= len(c.urls) {
		return nil, errors.New("RPC 주소가 설정되지 않았습니다")
	}
	name := label(i)
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%s: 요청을 만들 수 없습니다", name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.urls[i], bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: 주소 형식이 올바르지 않습니다", name)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// *url.Error and the dial error embed the URL or its host: drop the text.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: 요청이 중단되었습니다: %w", name, ctx.Err())
		}
		return nil, fmt.Errorf("%s: 연결하지 못했습니다", name)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP 상태 %d", name, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%s: 응답을 읽지 못했습니다", name)
	}
	if len(data) > maxBody {
		return nil, fmt.Errorf("%s: 응답이 1MiB를 넘습니다", name)
	}
	return data, nil
}

// validHexResult reports whether raw is a JSON string of the form 0x<hex>.
func validHexResult(raw json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	if len(s) < 2 || (s[:2] != "0x" && s[:2] != "0X") {
		return false
	}
	for _, ch := range s[2:] {
		switch {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f', ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}
