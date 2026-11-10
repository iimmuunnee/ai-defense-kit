package watch

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

// The XRPL JSON-RPC shapes used here follow the public documentation. They are
// exercised by tests against recorded-style answers, not against a live node.

const kindXRPL = "xrpl-wallet"

const (
	// maxSignerPages is how many pages of account_objects are followed. More is
	// an error: a list that was cut short must never be taken for the whole.
	maxSignerPages = 20
	// signerPageLimit is the page size asked of account_objects. How real servers
	// treat it is not verified; a list longer than the pages followed is an error.
	signerPageLimit = 400
	// xrplFutureMargin is how far ahead of now a ledger may have closed before
	// the node's answer is refused.
	xrplFutureMargin = 5 * time.Minute
	// rippleEpoch is 2000-01-01T00:00:00Z in Unix seconds.
	rippleEpoch = 946684800
)

const xrplAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

type xrplObserver struct {
	newClient  func(Target) *rpc.Client
	retryAfter time.Duration
	now        func() time.Time
}

// NewXRPLObserver returns the observer for kind "xrpl-wallet". It reads the
// signing authority of one account: regular key, signer list and account flags.
func NewXRPLObserver(newClient func(Target) *rpc.Client) Observer {
	return newXRPLObserver(newClient, DefaultRetryAfter)
}

func newXRPLObserver(newClient func(Target) *rpc.Client, retryAfter time.Duration) *xrplObserver {
	return &xrplObserver{newClient: newClient, retryAfter: retryAfter, now: time.Now}
}

func (o *xrplObserver) Kind() string { return kindXRPL }

func (o *xrplObserver) Observe(ctx context.Context, t Target) (Observation, error) {
	addr, err := parseXRPLAddress(t.Options["address"])
	if err != nil {
		return nil, err
	}
	maxAge, err := maxBlockAge(t.Options["max_block_age"])
	if err != nil {
		return nil, err
	}
	// From here on a failure keeps what has been read (see PartialError). The
	// address comes from the config, so an edited config is seen even when no
	// RPC answers.
	obs := Observation{"address": addr}
	x := xrplReader{c: o.newClient(t), key: t.Key, addr: addr, retryAfter: o.retryAfter, miss: missing{}}
	err = x.read(ctx, obs)
	if err == nil && maxAge > 0 {
		// Last, so that a change seen on a stuck node is still reported.
		err = x.checkLedgerAge(ctx, o.now(), maxAge)
	}
	// An RPC that did not answer leaves the values it did not confirm unverified.
	err = withMissing(err, x.miss)
	if err != nil {
		return nil, PartialError{Obs: obs, Err: err}
	}
	return obs, nil
}

type xrplReader struct {
	c          *rpc.Client
	key, addr  string
	retryAfter time.Duration
	miss       missing // endpoints that did not answer; shared by the reads of one observation
}

// xrplInfo is what account_info contributes to the observation.
type xrplInfo struct{ regularKey, flags string }

// read fills obs. Servers report different ledger positions and hashes, so
// what is compared between them are the extracted fields, never the raw
// answers. Fields from account_info come first: a failure of the signer list
// read keeps them.
func (x xrplReader) read(ctx context.Context, obs Observation) error {
	info, part, err := rpc.Agree(ctx, x.retryAfter, "account_info", func(ctx context.Context) ([]xrplInfo, []error) {
		return eachRPC(ctx, x.c, x.accountInfo)
	}, func(a, b xrplInfo) bool { return a == b })
	if err != nil {
		return fmt.Errorf("account_info: %w", err)
	}
	x.miss.add(part)
	obs["regular_key"] = info.regularKey
	obs["flags"] = info.flags

	signers, part, err := rpc.Agree(ctx, x.retryAfter, "account_objects", func(ctx context.Context) ([]string, []error) {
		return eachRPC(ctx, x.c, x.signerList)
	}, func(a, b string) bool { return a == b })
	if err != nil {
		return fmt.Errorf("account_objects: %w", err)
	}
	x.miss.add(part)
	obs["signer_list"] = signers
	return nil
}

// eachRPC runs f against every endpoint in order and returns one value and one
// error per endpoint, so that the ones that answer are still used. A client that
// was built failed (no usable address) returns its own error alone.
func eachRPC[T any](ctx context.Context, c *rpc.Client, f func(ctx context.Context, i int) (T, error)) ([]T, []error) {
	if c.Len() == 0 {
		_, err := c.PostJSON(ctx, 0, nil)
		return nil, []error{err}
	}
	out := make([]T, c.Len())
	errs := make([]error, c.Len())
	for i := range out {
		out[i], errs[i] = f(ctx, i)
	}
	return out, errs
}

// call sends one command to endpoint i and returns its result object. An
// answer is accepted only with status "success" and validated true. Nothing a
// server says about an error is repeated, except that actNotFound gets a
// message of its own.
func (x xrplReader) call(ctx context.Context, i int, method string, params map[string]any) (json.RawMessage, error) {
	data, err := x.c.PostJSON(ctx, i, map[string]any{"method": method, "params": []any{params}})
	if err != nil {
		return nil, err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("RPC %d: JSON 응답이 아닙니다", i+1)
	}
	var head struct {
		Status    string `json:"status"`
		Error     string `json:"error"`
		Validated *bool  `json:"validated"`
	}
	if len(env.Result) == 0 || json.Unmarshal(env.Result, &head) != nil {
		return nil, fmt.Errorf("RPC %d: 응답에 XRPL 결과가 없거나 형식이 올바르지 않습니다", i+1)
	}
	if head.Status != "success" {
		if head.Error == "actNotFound" {
			return nil, fmt.Errorf("대상 %s: RPC %d에서 계정을 찾지 못했습니다(actNotFound). 설정한 주소(address)가 잘못되었거나 아직 만들어지지 않은 계정일 수 있습니다", x.key, i+1)
		}
		return nil, fmt.Errorf("RPC %d: XRPL이 오류로 응답했습니다(status가 success가 아닙니다)", i+1)
	}
	if head.Validated == nil || !*head.Validated {
		return nil, fmt.Errorf("RPC %d: 검증된(validated) 레저의 값이 아닙니다", i+1)
	}
	return env.Result, nil
}

func (x xrplReader) accountInfo(ctx context.Context, i int) (xrplInfo, error) {
	raw, err := x.call(ctx, i, "account_info", map[string]any{"account": x.addr, "ledger_index": "validated"})
	if err != nil {
		return xrplInfo{}, err
	}
	var r struct {
		AccountData struct {
			Account    string  `json:"Account"`
			Flags      *uint32 `json:"Flags"`
			RegularKey string  `json:"RegularKey"`
		} `json:"account_data"`
	}
	bad := func(what string) (xrplInfo, error) {
		return xrplInfo{}, fmt.Errorf("RPC %d: account_info 결과의 %s", i+1, what)
	}
	if json.Unmarshal(raw, &r) != nil {
		return bad("형식이 올바르지 않습니다")
	}
	d := r.AccountData
	if d.Account != x.addr {
		return bad("계정이 설정한 address와 다릅니다")
	}
	if d.Flags == nil {
		return bad("Flags가 없거나 숫자가 아닙니다")
	}
	if d.RegularKey != "" && !validXRPLAddress(d.RegularKey) {
		return bad("RegularKey가 주소 형식이 아닙니다")
	}
	return xrplInfo{regularKey: d.RegularKey, flags: strconv.FormatUint(uint64(*d.Flags), 10)}, nil
}

// signerList reads the signer list objects of the account and returns them as
// text: one list is "quorum=<n>;<account>:<weight>,..." with the signers sorted
// by account; several lists are sorted and joined with "|". No list is "".
func (x xrplReader) signerList(ctx context.Context, i int) (string, error) {
	params := map[string]any{"account": x.addr, "type": "signer_list", "ledger_index": "validated", "limit": signerPageLimit}
	bad := func(what string) (string, error) {
		return "", fmt.Errorf("RPC %d: account_objects 결과의 %s", i+1, what)
	}
	var lists []string
	for page := 1; ; page++ {
		raw, err := x.call(ctx, i, "account_objects", params)
		if err != nil {
			return "", err
		}
		var r struct {
			Account string          `json:"account"`
			Marker  json.RawMessage `json:"marker"`
			Objects *[]struct {
				Type    string  `json:"LedgerEntryType"`
				Quorum  *uint32 `json:"SignerQuorum"`
				Entries []struct {
					Entry struct {
						Account string  `json:"Account"`
						Weight  *uint16 `json:"SignerWeight"`
					} `json:"SignerEntry"`
				} `json:"SignerEntries"`
			} `json:"account_objects"`
		}
		var idx struct {
			LedgerIndex *uint64 `json:"ledger_index"`
		}
		if json.Unmarshal(raw, &r) != nil || json.Unmarshal(raw, &idx) != nil || r.Objects == nil {
			return bad("형식이 올바르지 않습니다")
		}
		if r.Account != x.addr {
			return bad("계정이 설정한 address와 다릅니다")
		}
		for _, o := range *r.Objects {
			if o.Type != "SignerList" {
				return bad("항목 중 서명자 목록(SignerList)이 아닌 것이 있습니다")
			}
			if o.Quorum == nil || len(o.Entries) == 0 {
				return bad("서명자 목록에 SignerQuorum이나 서명자가 없습니다")
			}
			type signer struct {
				acct string
				w    uint16
			}
			var ss []signer
			for _, e := range o.Entries {
				if e.Entry.Weight == nil || !validXRPLAddress(e.Entry.Account) {
					return bad("서명자의 계정이나 SignerWeight가 올바르지 않습니다")
				}
				ss = append(ss, signer{e.Entry.Account, *e.Entry.Weight})
			}
			slices.SortFunc(ss, func(a, b signer) int {
				if c := strings.Compare(a.acct, b.acct); c != 0 {
					return c
				}
				return int(a.w) - int(b.w)
			})
			parts := make([]string, len(ss))
			for k, s := range ss {
				parts[k] = s.acct + ":" + strconv.Itoa(int(s.w))
			}
			lists = append(lists, fmt.Sprintf("quorum=%d;%s", *o.Quorum, strings.Join(parts, ",")))
		}
		if m := strings.TrimSpace(string(r.Marker)); m == "" || m == "null" {
			break
		}
		if page >= maxSignerPages {
			return "", fmt.Errorf("RPC %d: 서명자 목록이 %d쪽을 넘어 끝까지 읽지 못했습니다", i+1, maxSignerPages)
		}
		if idx.LedgerIndex == nil {
			return bad("ledger_index가 없어 다음 쪽을 같은 레저에서 읽을 수 없습니다")
		}
		// The next page is read from the ledger of the first one, so that the
		// pages are parts of one list.
		params["ledger_index"] = *idx.LedgerIndex
		params["marker"] = r.Marker
	}
	slices.Sort(lists)
	return strings.Join(lists, "|"), nil
}

// checkLedgerAge asks every URL for its latest validated ledger. A node that
// is stuck or still syncing answers consistently with an old state, so a
// difference from the other URLs is not enough to notice it, and with one URL
// there is no other.
func (x xrplReader) checkLedgerAge(ctx context.Context, now time.Time, maxAge time.Duration) error {
	_, errs := eachRPC(ctx, x.c, func(ctx context.Context, i int) (struct{}, error) {
		raw, err := x.call(ctx, i, "ledger", map[string]any{"ledger_index": "validated"})
		if err != nil {
			return struct{}{}, fmt.Errorf("ledger: %w", err)
		}
		var r struct {
			Ledger struct {
				CloseTime json.Number `json:"close_time"`
			} `json:"ledger"`
		}
		unread := fmt.Errorf("RPC %d: 최신 레저의 close_time을 읽지 못했습니다", i+1)
		if json.Unmarshal(raw, &r) != nil {
			return struct{}{}, verdictError{unread}
		}
		n, ok := new(big.Int).SetString(r.Ledger.CloseTime.String(), 10)
		if !ok || !n.IsInt64() || n.Sign() < 0 {
			return struct{}{}, verdictError{unread}
		}
		// close_time counts seconds from 2000-01-01. Both sides are int64
		// seconds and the closing time cannot be negative, so the difference
		// cannot overflow, whatever the server sent.
		diff := now.Unix() - rippleEpoch - n.Int64()
		maxSec := int64(maxAge / time.Second)
		switch {
		case diff > maxSec:
			return struct{}{}, verdictError{staleError{fmt.Sprintf("RPC %d: 최신 레저가 지금보다 %s 전에 닫혔습니다(허용 %s). 노드가 멈췄거나 동기화 중일 수 있습니다", i+1, shownSeconds(diff), maxAge)}}
		case -diff > int64(xrplFutureMargin/time.Second):
			// Only a ledger that is behind says the node may be stopped.
			return struct{}{}, verdictError{fmt.Errorf("RPC %d: 최신 레저의 시각이 지금보다 %s 앞서 있습니다(허용 %s). 노드의 시각이나 응답이 올바르지 않을 수 있습니다", i+1, shownSeconds(-diff), xrplFutureMargin)}
		}
		return struct{}{}, nil
	})
	return x.answered(errs)
}

// verdictError marks the failure of a node that answered but whose ledger is
// stale or implausible: a verdict on that node, not a missing answer.
type verdictError struct{ err error }

func (e verdictError) Error() string { return e.err.Error() }
func (e verdictError) Unwrap() error { return e.err }

// answered notes the endpoints that failed to answer as missing. A verdict on a
// node is returned; so is the failure of every endpoint.
func (x xrplReader) answered(errs []error) error {
	var p rpc.Partial
	var first, verdict error
	var v verdictError
	for i, err := range errs {
		switch {
		case err == nil:
		case errors.As(err, &v):
			if verdict == nil {
				verdict = v.err
			}
		default:
			if first == nil {
				first = err
			}
			p.Missing = append(p.Missing, i+1)
		}
	}
	if verdict != nil {
		return verdict
	}
	if len(p.Missing) == len(errs) {
		return first
	}
	x.miss.add(p)
	return nil
}

// shownSeconds words a number of seconds without overflowing a Duration.
func shownSeconds(s int64) string {
	const century = int64(100 * 365 * 24 * 3600)
	if s > century {
		return "100년 넘게"
	}
	return (time.Duration(s) * time.Second).String()
}

// knownXRPLOptions lists the options of an xrpl-wallet target.
var knownXRPLOptions = map[string]bool{"address": true, "rpc_url_env": true, "max_block_age": true}

// validateXRPLOptions finds mistakes at load time: an option name with a typo
// is ignored otherwise, and a wrong address would read as a different account.
func validateXRPLOptions(opts map[string]any) error {
	for _, k := range slices.Sorted(maps.Keys(opts)) {
		if !knownXRPLOptions[k] {
			return fmt.Errorf("알 수 없는 옵션 %q입니다", k)
		}
	}
	if _, err := parseXRPLAddress(opts["address"]); err != nil {
		return err
	}
	_, err := maxBlockAge(opts["max_block_age"])
	return err
}

// parseXRPLAddress checks the address option: a classic address. The value is
// not repeated in the error.
func parseXRPLAddress(v any) (string, error) {
	s, ok := v.(string)
	if v != nil && !ok {
		return "", errors.New("address: " + errAddressNotText)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("address 옵션이 없습니다")
	}
	if validXRPLAddress(s) {
		return s, nil
	}
	if (s[0] == 'X' || s[0] == 'T') && (len(s) == 46 || len(s) == 47) {
		return "", errors.New("address: X-address는 지원하지 않습니다. r로 시작하는 클래식 주소를 적으세요")
	}
	return "", errors.New("address가 올바른 XRPL 클래식 주소(r로 시작, 체크섬 포함)가 아닙니다")
}

// validXRPLAddress reports whether s is a classic address: base58 with the
// XRPL alphabet, 25 bytes holding version 0, a 20-byte account ID and the first
// four bytes of a double SHA-256 as checksum.
func validXRPLAddress(s string) bool {
	if len(s) < 25 || len(s) > 35 {
		return false
	}
	n, leading, counting := new(big.Int), 0, true
	base := big.NewInt(58)
	for _, ch := range s {
		d := strings.IndexRune(xrplAlphabet, ch)
		if d < 0 {
			return false
		}
		if counting && d == 0 {
			leading++
		} else {
			counting = false
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(d)))
	}
	full := append(make([]byte, leading), n.Bytes()...)
	if len(full) != 25 || full[0] != 0 {
		return false
	}
	h1 := sha256.Sum256(full[:21])
	h2 := sha256.Sum256(h1[:])
	return string(h2[:4]) == string(full[21:])
}
