package watch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

const kindWeb = "web-scripts"

const (
	// webMaxBody is the most bytes read from one response. A longer one is an
	// error, never a truncated read: a hash of part of a script says nothing.
	webMaxBody = 5 << 20
	// webMaxRedirects is how many redirects one request may follow.
	webMaxRedirects = 5
	webTimeout      = 15 * time.Second
	// webMaxScripts is how many different script addresses of one page are read.
	webMaxScripts = 200
	// notFetched is the value of a script on a host that is not allowed. It is
	// a field of its own, so a new outside script still reads as a change.
	notFetched = "not-fetched"
)

var (
	errRedirectOutside = errors.New("허용된 호스트 밖으로 넘기려 해서 따라가지 않았습니다")
	errTooManyRedirect = errors.New("리다이렉트가 너무 많습니다")
)

// knownWebOptions lists the options of a web-scripts target.
var knownWebOptions = map[string]bool{"url": true, "extra_scripts": true, "allowed_hosts": true}

// webOptions are the checked options of a web-scripts target.
type webOptions struct {
	page    *url.URL // as written, without the fragment
	extra   []*url.URL
	allowed map[string]bool // origins (scheme, host and port) the scripts may come from
}

// originKey is the scheme, host and port of u, with the default port of the
// scheme made explicit. http://h and https://h are different origins, and so
// are different ports.
func originKey(u *url.URL) string {
	p := u.Port()
	if p == "" {
		p = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), p)
}

// allowedOrigin reads an allowed_hosts entry. Without a port it means that
// host on the default port of the page's scheme; host:443 is https, host:80 is
// http, and any other port uses the page's scheme.
func allowedOrigin(entry, pageScheme string) (string, bool) {
	host, port := entry, ""
	switch {
	case strings.HasPrefix(entry, "["):
		h, p, err := net.SplitHostPort(entry)
		if err == nil {
			host, port = h, p
		} else {
			host = strings.Trim(entry, "[]")
		}
	case strings.Count(entry, ":") == 1:
		h, p, err := net.SplitHostPort(entry)
		if err != nil {
			return "", false
		}
		host, port = h, p
	}
	if host == "" {
		return "", false
	}
	scheme := pageScheme
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		switch n {
		case 443:
			scheme = "https"
		case 80:
			scheme = "http"
		}
	}
	return originKey(&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}), true
}

// hostKey is the host of u with its port, in lower case. A port that is the
// default of the scheme is left out.
func hostKey(u *url.URL) string {
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	switch p := u.Port(); {
	case p == "", u.Scheme == "https" && p == "443", u.Scheme == "http" && p == "80":
		return h
	default:
		return h + ":" + p
	}
}

// shownURL is u as it may be written anywhere: scheme, host and path. The user
// information, the query and the fragment are dropped, because they can hold
// a password or a token and change on every deploy.
func shownURL(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return u.Scheme + "://" + hostKey(u) + p
}

// parseWebURL reads s as an absolute http or https address. The error names
// the option only, never the value.
func parseWebURL(option, s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%s: http:// 또는 https://로 시작하는 전체 주소여야 합니다", option)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s: http:// 또는 https://로 시작하는 전체 주소여야 합니다", option)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s: 주소에 사용자 이름이나 비밀번호(user:password@)를 넣을 수 없습니다", option)
	}
	return u, nil
}

func stringList(option string, v any) ([]string, error) {
	var out []string
	switch l := v.(type) {
	case nil:
		return nil, nil
	case []string:
		out = l
	case []any:
		for _, e := range l {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%s: 문자열 목록이어야 합니다", option)
			}
			out = append(out, s)
		}
	default:
		return nil, fmt.Errorf("%s: 문자열 목록이어야 합니다", option)
	}
	return out, nil
}

func parseWebOptions(opts map[string]any) (webOptions, error) {
	for _, k := range slices.Sorted(maps.Keys(opts)) {
		if !knownWebOptions[k] {
			return webOptions{}, fmt.Errorf("알 수 없는 옵션 %q입니다", k)
		}
	}
	raw, ok := opts["url"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return webOptions{}, errors.New("url 옵션에 페이지 주소를 문자열로 적어야 합니다")
	}
	page, err := parseWebURL("url", raw)
	if err != nil {
		return webOptions{}, err
	}
	page.Fragment = ""
	w := webOptions{page: page, allowed: map[string]bool{originKey(page): true}}

	hosts, err := stringList("allowed_hosts", opts["allowed_hosts"])
	if err != nil {
		return webOptions{}, err
	}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.ContainsAny(h, "/@?# \t") || strings.Contains(h, "://") {
			return webOptions{}, errors.New("allowed_hosts: 호스트 이름만 적어야 합니다 (주소나 경로, 사용자 정보 없이 example.com 또는 example.com:8443 꼴)")
		}
		o, ok := allowedOrigin(h, page.Scheme)
		if !ok {
			return webOptions{}, errors.New("allowed_hosts: 호스트 이름만 적어야 합니다 (주소나 경로, 사용자 정보 없이 example.com 또는 example.com:8443 꼴)")
		}
		w.allowed[o] = true
	}
	extras, err := stringList("extra_scripts", opts["extra_scripts"])
	if err != nil {
		return webOptions{}, err
	}
	for i, e := range extras {
		u, err := parseWebURL(fmt.Sprintf("extra_scripts의 %d번째", i+1), e)
		if err != nil {
			return webOptions{}, err
		}
		if !w.allows(u) {
			return webOptions{}, fmt.Errorf("extra_scripts의 %d번째: 페이지와 같은 호스트이거나 allowed_hosts에 있는 호스트여야 합니다", i+1)
		}
		u.Fragment = ""
		w.extra = append(w.extra, u)
	}
	return w, nil
}

// allows reports whether u is on the page's origin or an allowed one.
func (w webOptions) allows(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && w.allowed[originKey(u)]
}

// UnreadScripts counts the scripts of a web-scripts observation whose content
// was not read because their host is not allowed.
func UnreadScripts(obs Observation) int {
	n := 0
	for k, v := range obs {
		if strings.HasPrefix(k, "script:") && v == notFetched {
			n++
		}
	}
	return n
}

// PlainHTTPPage reports whether a web-scripts target reads over plain http from
// something other than this machine.
func PlainHTTPPage(t Target) bool {
	if t.Kind != kindWeb {
		return false
	}
	w, err := parseWebOptions(t.Options)
	if err != nil {
		return false
	}
	plain := func(u *url.URL) bool { return u.Scheme == "http" && !isLocalHost(u.Hostname()) }
	return plain(w.page) || slices.ContainsFunc(w.extra, plain)
}

func validateWebOptions(opts map[string]any) error {
	_, err := parseWebOptions(opts)
	return err
}

type webObserver struct {
	allowEnvProxy bool
}

// NewWebObserver returns the observer for kind "web-scripts". It connects to
// the page's host and to allowed_hosts only. A proxy set in the environment
// is used only with allowEnvProxy.
func NewWebObserver(allowEnvProxy bool) Observer { return &webObserver{allowEnvProxy: allowEnvProxy} }

func (*webObserver) Kind() string { return kindWeb }

// client follows redirects only to hosts in allowed, a few times.
func (o *webObserver) client(w webOptions) *http.Client {
	return &http.Client{
		Timeout:   webTimeout,
		Transport: rpc.Transport(o.allowEnvProxy),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > webMaxRedirects {
				return errTooManyRedirect
			}
			if !w.allows(req.URL) {
				return errRedirectOutside
			}
			// The address of the page can hold a token: never hand it on.
			req.Header.Del("Referer")
			return nil
		},
	}
}

// fetchError says why a read failed without repeating any address: the
// standard library puts the whole URL, query included, into its errors.
func fetchError(ctx context.Context, err error) error {
	var ne net.Error
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case errors.Is(err, errRedirectOutside):
		return errRedirectOutside
	case errors.Is(err, errTooManyRedirect):
		return errTooManyRedirect
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return errors.New("시간이 초과되었습니다")
	}
	return errors.New("연결하지 못했습니다")
}

// get reads one response of at most webMaxBody bytes. Anything but a 2xx is
// an error: an error page is never compared as if it were the content.
func get(ctx context.Context, c *http.Client, u string) (body []byte, final *url.URL, ctype string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, "", errors.New("요청을 만들지 못했습니다")
	}
	req.Header.Set("User-Agent", "adk-watch")
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, "", fetchError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, "", fmt.Errorf("HTTP 상태 %d", resp.StatusCode)
	}
	if resp.ContentLength > webMaxBody {
		return nil, nil, "", errors.New("응답이 5MiB를 넘습니다")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, webMaxBody+1))
	if err != nil {
		return nil, nil, "", fetchError(ctx, err)
	}
	if len(b) > webMaxBody {
		return nil, nil, "", errors.New("응답이 5MiB를 넘습니다")
	}
	return b, resp.Request.URL, resp.Header.Get("Content-Type"), nil
}

func isHTML(ctype string) bool {
	mt, _, err := mime.ParseMediaType(ctype)
	return err == nil && (mt == "text/html" || mt == "application/xhtml+xml")
}

// scriptSources returns the src of every script element and the page's
// <base href>, if it has one. Inline scripts have no src and are not hashed.
func scriptSources(body []byte) (srcs []string, base string, err error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, a := range n.Attr {
				switch {
				case n.Data == "script" && a.Key == "src":
					if s := strings.TrimSpace(a.Val); s != "" {
						srcs = append(srcs, s)
					}
				case n.Data == "base" && a.Key == "href" && base == "":
					base = strings.TrimSpace(a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return srcs, base, nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (o *webObserver) Observe(ctx context.Context, t Target) (Observation, error) {
	w, err := parseWebOptions(t.Options)
	if err != nil {
		return nil, err
	}
	c := o.client(w)

	body, final, ctype, err := get(ctx, c, w.page.String())
	if err != nil {
		return nil, fmt.Errorf("페이지를 읽지 못했습니다: %w", err)
	}
	if !isHTML(ctype) {
		return nil, errors.New("페이지가 HTML이 아닌 형식으로 응답했습니다")
	}
	srcs, baseHref, err := scriptSources(body)
	if err != nil {
		return nil, errors.New("페이지를 해석하지 못했습니다")
	}
	base := final
	if baseHref != "" {
		if b, err := url.Parse(baseHref); err == nil {
			base = final.ResolveReference(b)
		}
	}

	obs := Observation{"url": shownURL(w.page)}
	// values holds the distinct values seen for each field. Scripts whose
	// addresses differ only in the query share a field.
	values := map[string]map[string]bool{}
	failedField := map[string]bool{}
	var failures []string
	record := func(field, value string) {
		if values[field] == nil {
			values[field] = map[string]bool{}
		}
		values[field][value] = true
	}

	// The scripts the user named come first: the page cannot push them past the cap.
	targets := slices.Clone(w.extra)
	for _, s := range srcs {
		ref, err := url.Parse(s)
		if err != nil {
			failures = append(failures, "해석할 수 없는 스크립트 주소가 있습니다")
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			// data: and the like: there is nothing to fetch, but the text itself is the content.
			record("script:"+strings.ToLower(abs.Scheme)+":", sha256Hex([]byte(s)))
			continue
		}
		targets = append(targets, abs)
	}

	seen := map[string]bool{}
	distinct := 0
	for _, u := range targets {
		u.User, u.Fragment = nil, ""
		full := u.String()
		if seen[full] {
			continue
		}
		seen[full] = true
		distinct++
		field := "script:" + shownURL(u)
		// Past the cap or the deadline a field is left out whole: a value made
		// from some of its scripts would read as a change.
		if distinct > webMaxScripts || ctx.Err() != nil {
			failedField[field] = true
			continue
		}
		if !w.allows(u) {
			record(field, notFetched)
			continue
		}
		b, _, _, err := get(ctx, c, full)
		if err != nil {
			failedField[field] = true
			if ctx.Err() == nil {
				failures = append(failures, fmt.Sprintf("%s: %v", field, err))
			}
			continue
		}
		record(field, sha256Hex(b))
	}

	for field, vs := range values {
		if failedField[field] {
			continue
		}
		obs[field] = combine(vs)
	}
	switch err := ctx.Err(); {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded):
		return nil, PartialError{Obs: obs, Err: errDeadline}
	default:
		return nil, err
	}
	var msg string
	if len(failures) > 0 {
		slices.Sort(failures)
		msg = strings.Join(failures[:min(len(failures), 3)], "; ")
		if len(failures) > 3 {
			msg += fmt.Sprintf(" 외 %d건", len(failures)-3)
		}
	}
	if distinct > webMaxScripts {
		capped := fmt.Sprintf("페이지의 스크립트 주소가 %d개로 상한 %d개를 넘어 나머지는 읽지 않았습니다", distinct, webMaxScripts)
		if msg != "" {
			capped += "; "
		}
		msg = capped + msg
	}
	if msg != "" {
		return nil, PartialError{Obs: obs, Err: errors.New("스크립트를 다 읽지 못했습니다: " + msg)}
	}
	return obs, nil
}

// combine is the one value of a field. Several distinct values are hashed
// together in sorted order, so the order on the page does not matter.
func combine(vs map[string]bool) string {
	if len(vs) == 1 {
		for v := range vs {
			return v
		}
	}
	return sha256Hex([]byte(strings.Join(slices.Sorted(maps.Keys(vs)), "\n")))
}

// checkInitialWeb refuses a page with no script that was read: a wrong
// address, a page that failed to load scripts, or scripts that are all on a
// host that is not allowed would read clean forever.
func checkInitialWeb(t Target, obs Observation) error {
	total := 0
	for k := range obs {
		if strings.HasPrefix(k, "script:") {
			total++
		}
	}
	switch {
	case total == 0:
		return fmt.Errorf("대상 %s: 페이지에서 스크립트를 하나도 찾지 못했고 extra_scripts도 없습니다. 주소가 잘못되었을 수 있습니다", t.Key)
	case UnreadScripts(obs) == total:
		return fmt.Errorf("대상 %s: 스크립트 %d개가 모두 allowed_hosts에 없는 호스트에 있어 내용을 하나도 읽지 못했습니다. 이대로는 스크립트가 바뀌어도 알 수 없습니다. 믿는 호스트를 allowed_hosts에 적으세요", t.Key, total)
	}
	return nil
}
