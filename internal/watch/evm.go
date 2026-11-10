package watch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

// DefaultRetryAfter is how long to wait before asking again when RPC
// endpoints disagree.
const DefaultRetryAfter = 3 * time.Second

// DefaultMaxBlockAge is how far the latest block of an RPC may be from now
// before the RPC counts as stuck. It is a judgement call that has not been
// measured on real chains.
const DefaultMaxBlockAge = 15 * time.Minute

// conn is a client together with the endpoints that did not answer during one
// observation.
type conn struct {
	*rpc.Client
	miss missing
}

// answered notes the endpoints with an error as missing and returns the
// positions (from 0) of the ones that answered. If none answered it returns the
// first error.
func (c *conn) answered(errs []error) ([]int, error) {
	var ok []int
	var first error
	var p rpc.Partial
	for i, err := range errs {
		if err != nil {
			if first == nil {
				first = err
			}
			p.Missing = append(p.Missing, i+1)
			continue
		}
		ok = append(ok, i)
	}
	if len(ok) == 0 {
		if first == nil {
			first = errors.New("RPC 주소가 설정되지 않았습니다")
		}
		return nil, first
	}
	c.miss.add(p)
	return ok, nil
}

// missing holds the positions (from 1) of RPC endpoints that did not answer.
type missing map[int]bool

func (m missing) add(p rpc.Partial) {
	for _, i := range p.Missing {
		m[i] = true
	}
}

// crossCheckError is the reason of a target read while some of its RPC
// endpoints did not answer: what the others said was compared with the baseline,
// but could not be checked against the missing ones. It names positions only.
type crossCheckError struct{ missing []int }

func (e crossCheckError) Error() string {
	parts := make([]string, len(e.missing))
	for i, n := range e.missing {
		parts[i] = fmt.Sprintf("RPC %d", n)
	}
	return "교차 확인 못 함: " + strings.Join(parts, ", ")
}

// CrossCheckMissing returns the positions (from 1) of the RPC endpoints that
// did not answer, when err says so; otherwise nil.
func CrossCheckMissing(err error) []int {
	var ce crossCheckError
	if errors.As(err, &ce) {
		return ce.missing
	}
	return nil
}

// withMissing adds the cross-check note to err, or turns a nil err into it when
// some endpoint did not answer.
func withMissing(err error, m missing) error {
	if len(m) == 0 {
		return err
	}
	ce := crossCheckError{missing: slices.Sorted(maps.Keys(m))}
	if err == nil {
		return ce
	}
	return wrapped{err, ce}
}

// wrapped is err with the cross-check note; it matches both under errors.Is and
// errors.As.
type wrapped struct {
	err   error
	cross crossCheckError
}

func (w wrapped) Error() string   { return w.err.Error() + " (" + w.cross.Error() + ")" }
func (w wrapped) Unwrap() []error { return []error{w.err, w.cross} }

// ErrStale is wrapped by the error of a read from a node whose latest block is
// too old. Compare uses it to lower the confidence of what that node said.
var ErrStale = errors.New("노드가 멈춘 것으로 보입니다")

// staleError is the error text of a stale read. It matches ErrStale under
// errors.Is without repeating ErrStale's own text.
type staleError struct{ msg string }

func (e staleError) Error() string        { return e.msg }
func (e staleError) Is(target error) bool { return target == ErrStale }

const kindEVM = "evm-wallet"

const zeroAddress = "0x0000000000000000000000000000000000000000"

const (
	selGetOwners    = "0xa0e67e2b" // getOwners()
	selGetThreshold = "0xe75235b8" // getThreshold()
	slotZero        = "0x0"
	// EIP-1967 slots.
	slotImplementation = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	slotAdmin          = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)

var delegationPrefix = []byte{0xef, 0x01, 0x00}

type evmObserver struct {
	newClient  func(Target) *rpc.Client
	retryAfter time.Duration
	now        func() time.Time
}

// NewEVMObserver returns the observer for kind "evm-wallet".
func NewEVMObserver(newClient func(Target) *rpc.Client) Observer {
	return newEVMObserver(newClient, DefaultRetryAfter)
}

func newEVMObserver(newClient func(Target) *rpc.Client, retryAfter time.Duration) Observer {
	return &evmObserver{newClient: newClient, retryAfter: retryAfter, now: time.Now}
}

func (o *evmObserver) Kind() string { return kindEVM }

// NewEnvClient builds a client from the target's rpc_url_env option: a
// comma-separated list of environment variable names, each holding one URL.
// If anything is wrong the returned client fails every call; the error names
// the variable only, never a URL. The client ignores proxies set in the
// environment.
func NewEnvClient(t Target) *rpc.Client { return envClient(t, false) }

// EnvClients returns NewEnvClient, or with allowEnvProxy the same thing using
// the proxy set in the environment.
func EnvClients(allowEnvProxy bool) func(Target) *rpc.Client {
	return func(t Target) *rpc.Client { return envClient(t, allowEnvProxy) }
}

func envClient(t Target, allowEnvProxy bool) *rpc.Client {
	raw, ok := t.Options["rpc_url_env"].(string)
	if !ok || strings.TrimSpace(raw) == "" {
		return rpc.NewFailed(errors.New("rpc_url_env 옵션에 환경 변수 이름을 쉼표로 구분해 적어야 합니다"))
	}
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" && !ValidEnvName(name) {
			// The value is not echoed: it may be an address with a key in it.
			return rpc.NewFailed(fmt.Errorf("대상 %s: rpc_url_env에는 주소가 아니라 환경 변수 이름을 적어야 합니다", t.Key))
		}
	}
	var urls []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			return rpc.NewFailed(errors.New("rpc_url_env에 빈 환경 변수 이름이 있습니다"))
		}
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return rpc.NewFailed(fmt.Errorf("환경 변수 %s가 없거나 비어 있습니다", name))
		}
		urls = append(urls, v)
	}
	if allowEnvProxy {
		return rpc.NewWithEnvProxy(urls)
	}
	return rpc.New(urls, nil)
}

func (o *evmObserver) Observe(ctx context.Context, t Target) (Observation, error) {
	chainID, err := parseChainID(t.Options["chain_id"])
	if err != nil {
		return nil, err
	}
	addr, err := parseAddress(t.Options["address"])
	if err != nil {
		return nil, err
	}
	typ, _ := t.Options["type"].(string)
	switch typ {
	case "eoa", "safe", "proxy", "contract":
	case "":
		return nil, errors.New("type 옵션이 없습니다 (eoa, safe, proxy, contract 중 하나)")
	default:
		return nil, fmt.Errorf("type %q를 알 수 없습니다 (eoa, safe, proxy, contract 중 하나)", typ)
	}

	maxAge, err := maxBlockAge(t.Options["max_block_age"])
	if err != nil {
		return nil, err
	}

	// From here on a failure keeps what has been read: see PartialError. The
	// address and type come from the config, so an edited config is seen even
	// when no RPC answers.
	obs := Observation{"address": addr, "type": typ}
	c := &conn{Client: o.newClient(t), miss: missing{}}
	err = o.read(ctx, c, chainID, addr, typ, obs)
	if err == nil && maxAge > 0 {
		// Last, so that a change seen on a stuck node is still reported.
		err = o.checkBlockAge(ctx, c, maxAge)
	}
	// An RPC that did not answer leaves the values it did not confirm unverified.
	err = withMissing(err, c.miss)
	if err != nil {
		return nil, PartialError{Obs: obs, Err: err}
	}
	return obs, nil
}

// checkBlockAge asks every URL for its latest block. A node that is stuck or
// still syncing answers consistently with an old state, so a difference from
// the other URLs is not enough to notice it, and with one URL there is no other.
func (o *evmObserver) checkBlockAge(ctx context.Context, c *conn, maxAge time.Duration) error {
	res, errs := c.CallEachRaw(ctx, "eth_getBlockByNumber", []any{"latest", false})
	answered, err := c.answered(errs)
	if err != nil {
		return fmt.Errorf("eth_getBlockByNumber: %w", err)
	}
	now := o.now()
	for _, i := range answered {
		raw := res[i]
		ts, err := blockTime(raw)
		if err != nil {
			return fmt.Errorf("RPC %d: 최신 블록의 시각을 읽지 못했습니다", i+1)
		}
		age := now.Sub(ts)
		behind := age > 0
		if age < 0 {
			age = -age
		}
		if age > maxAge {
			msg := fmt.Sprintf("RPC %d: 최신 블록의 시각이 지금과 %s 차이 납니다(허용 %s). 노드가 멈췄거나 동기화 중일 수 있습니다", i+1, age.Round(time.Second), maxAge)
			if behind {
				// Only a block that is behind says the node may be stopped.
				return staleError{msg}
			}
			return errors.New(msg)
		}
	}
	return nil
}

func blockTime(raw json.RawMessage) (time.Time, error) {
	var b struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return time.Time{}, err
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(b.Timestamp, "0x"), "0X"), 16)
	if !ok || !n.IsInt64() {
		return time.Time{}, errors.New("timestamp")
	}
	return time.Unix(n.Int64(), 0), nil
}

// maxBlockAge reads the max_block_age option: a duration, 0 turns the check off.
func maxBlockAge(v any) (time.Duration, error) {
	bad := errors.New(`max_block_age는 "15m"처럼 단위가 있는 시간이나 "0"(끄기)이어야 합니다`)
	switch x := v.(type) {
	case nil:
		return DefaultMaxBlockAge, nil
	case int:
		if x == 0 {
			return 0, nil
		}
	case string:
		if d, err := time.ParseDuration(strings.TrimSpace(x)); err == nil && d >= 0 {
			return d, nil
		}
	}
	return 0, bad
}

// knownEVMOptions lists the options of an evm-wallet target.
var knownEVMOptions = map[string]bool{
	"chain_id": true, "address": true, "type": true, "rpc_url_env": true,
	"allowed_delegates": true, "max_block_age": true,
}

// validateEVMOptions finds mistakes that would otherwise pass quietly: an
// option name with a typo is ignored, and YAML reads an unquoted short address
// as a number.
func validateEVMOptions(opts map[string]any) error {
	for _, k := range slices.Sorted(maps.Keys(opts)) {
		if !knownEVMOptions[k] {
			return fmt.Errorf("알 수 없는 옵션 %q입니다", k)
		}
	}
	if v, ok := opts["address"]; ok {
		if _, isText := v.(string); !isText {
			return errors.New(errAddressNotText)
		}
	}
	if list, ok := opts["allowed_delegates"].([]any); ok {
		for _, v := range list {
			if _, isText := v.(string); !isText {
				return errors.New("allowed_delegates: " + errAddressNotText)
			}
		}
	}
	_, err := maxBlockAge(opts["max_block_age"])
	return err
}

const errAddressNotText = "주소는 따옴표로 감싼 문자열로 적어야 합니다 (따옴표가 없으면 YAML이 숫자로 읽습니다)"

// read fills obs field by field. The code and the logic contract come first:
// when the logic of a Safe is replaced, the owner calls are the ones that fail.
func (o *evmObserver) read(ctx context.Context, c *conn, chainID *big.Int, addr, typ string, obs Observation) error {
	if err := checkChainID(ctx, c, chainID); err != nil {
		return err
	}
	obs["chain_id"] = chainID.String()

	code, err := o.bytes(ctx, c, "eth_getCode", addr, "latest")
	if err != nil {
		return err
	}

	switch typ {
	case "eoa":
		switch {
		case len(code) == 0:
			obs["delegate"] = ""
		case bytes.HasPrefix(code, delegationPrefix):
			if len(code) != len(delegationPrefix)+20 {
				return errors.New("위임 코드(0xef0100)의 길이가 올바르지 않습니다")
			}
			obs["delegate"] = "0x" + hex.EncodeToString(code[len(delegationPrefix):])
		default:
			obs["delegate"] = ""
			obs["code_sha256"] = codeHash(code)
		}
	case "safe":
		obs["code_sha256"] = codeHash(code)
		mc, err := o.slotAddress(ctx, c, addr, slotZero)
		if err != nil {
			return err
		}
		obs["master_copy"] = mc
		owners, err := o.owners(ctx, c, addr)
		if err != nil {
			return err
		}
		obs["owners"] = strings.Join(owners, ",")
		thr, err := o.call(ctx, c, addr, selGetThreshold)
		if err != nil {
			return err
		}
		if len(thr) != 32 {
			return errors.New("getThreshold 결과가 32바이트가 아닙니다")
		}
		obs["threshold"] = new(big.Int).SetBytes(thr).String()
	case "proxy":
		obs["code_sha256"] = codeHash(code)
		impl, err := o.slotAddress(ctx, c, addr, slotImplementation)
		if err != nil {
			return err
		}
		obs["implementation"] = impl
		admin, err := o.slotAddress(ctx, c, addr, slotAdmin)
		if err != nil {
			return err
		}
		obs["admin"] = admin
	case "contract":
		obs["code_sha256"] = codeHash(code)
	}
	return nil
}

func codeHash(code []byte) string {
	s := sha256.Sum256(code)
	return hex.EncodeToString(s[:])
}

// bytes runs an Agreed read whose result is a hex string and decodes it.
func (o *evmObserver) bytes(ctx context.Context, c *conn, method string, params ...any) ([]byte, error) {
	raw, part, err := c.Agreed(ctx, method, params, o.retryAfter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	c.miss.add(part)
	b, err := decodeHexResult(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	return b, nil
}

// call runs eth_call and requires a non-empty answer.
func (o *evmObserver) call(ctx context.Context, c *conn, addr, selector string) ([]byte, error) {
	b, err := o.bytes(ctx, c, "eth_call", map[string]string{"to": addr, "data": selector}, "latest")
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("eth_call %s가 빈 값(0x)을 돌려주었습니다: 주소나 type이 잘못되었을 수 있습니다", selector)
	}
	return b, nil
}

func (o *evmObserver) slotAddress(ctx context.Context, c *conn, addr, slot string) (string, error) {
	b, err := o.bytes(ctx, c, "eth_getStorageAt", addr, slot, "latest")
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("슬롯 %s의 값이 32바이트가 아닙니다", slot)
	}
	if !allZero(b[:12]) {
		return "", fmt.Errorf("슬롯 %s의 앞 12바이트가 0이 아니어서 주소로 읽을 수 없습니다", slot)
	}
	return "0x" + hex.EncodeToString(b[12:]), nil
}

// owners reads getOwners() and decodes the ABI-encoded address[] result.
func (o *evmObserver) owners(ctx context.Context, c *conn, addr string) ([]string, error) {
	b, err := o.call(ctx, c, addr, selGetOwners)
	if err != nil {
		return nil, err
	}
	bad := errors.New("getOwners 결과의 ABI 형식이 올바르지 않습니다")
	if len(b) < 64 {
		return nil, bad
	}
	off := new(big.Int).SetBytes(b[:32])
	if !off.IsUint64() || off.Uint64() > uint64(len(b)-32) {
		return nil, bad
	}
	start := int(off.Uint64())
	n := new(big.Int).SetBytes(b[start : start+32])
	body := b[start+32:]
	if !n.IsUint64() || n.Uint64() > uint64(len(body)/32) {
		return nil, bad
	}
	out := make([]string, 0, n.Uint64())
	for i := 0; i < int(n.Uint64()); i++ {
		w := body[i*32 : (i+1)*32]
		if !allZero(w[:12]) {
			return nil, bad
		}
		out = append(out, "0x"+hex.EncodeToString(w[12:]))
	}
	sort.Strings(out)
	return out, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func decodeHexResult(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("결과가 문자열이 아닙니다")
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("결과를 16진수로 읽을 수 없습니다")
	}
	return b, nil
}

// checkChainID asks every configured URL for eth_chainId and requires each
// to match want.
func checkChainID(ctx context.Context, c *conn, want *big.Int) error {
	res, errs := c.CallEach(ctx, "eth_chainId", nil)
	answered, err := c.answered(errs)
	if err != nil {
		return fmt.Errorf("eth_chainId: %w", err)
	}
	for _, i := range answered {
		raw := res[i]
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("RPC %d: eth_chainId 결과가 문자열이 아닙니다", i+1)
		}
		got, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"), 16)
		if !ok {
			return fmt.Errorf("RPC %d: eth_chainId 결과를 읽을 수 없습니다", i+1)
		}
		if got.Cmp(want) != 0 {
			return fmt.Errorf("RPC %d의 체인 ID(%s)가 설정(%s)과 다릅니다", i+1, got, want)
		}
	}
	return nil
}

func parseChainID(v any) (*big.Int, error) {
	bad := errors.New("chain_id가 없거나 올바르지 않습니다 (10진수 또는 0x 16진수 정수여야 합니다)")
	switch x := v.(type) {
	case int:
		return nonNeg(big.NewInt(int64(x)), bad)
	case int64:
		return nonNeg(big.NewInt(x), bad)
	case uint64:
		return new(big.Int).SetUint64(x), nil
	case string:
		s := strings.TrimSpace(x)
		base := 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s, base = s[2:], 16
		}
		if s == "" || strings.ContainsAny(s, "+- _") {
			return nil, bad
		}
		n, ok := new(big.Int).SetString(s, base)
		if !ok {
			return nil, bad
		}
		return n, nil
	}
	return nil, bad
}

func nonNeg(n *big.Int, err error) (*big.Int, error) {
	if n.Sign() < 0 {
		return nil, err
	}
	return n, nil
}

func parseAddress(v any) (string, error) {
	s, ok := v.(string)
	if v != nil && !ok {
		return "", errors.New("address: " + errAddressNotText)
	}
	if s == "" {
		return "", errors.New("address 옵션이 없습니다")
	}
	h := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 20 {
		return "", errors.New("address는 16진수 20바이트여야 합니다")
	}
	return "0x" + hex.EncodeToString(b), nil
}

// SingleEndpoint reports whether an evm-wallet or xrpl-wallet target reads from fewer than
// two different RPC addresses, so its answers cannot be cross-checked. The
// addresses are compared, not their names: two names can hold one address. A
// variable that is not set counts by its name; reading it fails anyway.
func SingleEndpoint(t Target) bool {
	if !readsThroughRPC(t.Kind) {
		return false
	}
	seen := map[string]bool{}
	for _, name := range envNames(t) {
		v := strings.TrimRight(strings.TrimSpace(os.Getenv(name)), "/")
		if v == "" {
			v = "unset:" + name
		}
		seen[v] = true
	}
	return len(seen) < 2
}

// PlainHTTPEndpoints returns the positions (from 1) of RPC addresses that use
// plain http to something other than this machine.
func PlainHTTPEndpoints(t Target) []int {
	if !readsThroughRPC(t.Kind) {
		return nil
	}
	var out []int
	for i, name := range envNames(t) {
		u, err := url.Parse(strings.TrimSpace(os.Getenv(name)))
		if err == nil && u.Scheme == "http" && !isLocalHost(u.Hostname()) {
			out = append(out, i+1)
		}
	}
	return out
}

// readsThroughRPC reports whether targets of the kind are read from RPC
// addresses named by rpc_url_env.
func readsThroughRPC(kind string) bool { return kind == kindEVM || kind == kindXRPL }

func isLocalHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func envNames(t Target) []string {
	raw, _ := t.Options["rpc_url_env"].(string)
	var out []string
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// checkInitialEVM refuses what points to a wrong address or type. A proxy may
// have no admin (UUPS).
func checkInitialEVM(t Target, obs Observation) error {
	wrong := func(what string) error {
		return fmt.Errorf("대상 %s: %s. 주소나 type이 잘못되었을 수 있습니다", t.Key, what)
	}
	typ := obs["type"]
	if typ != "eoa" && obs["code_sha256"] == codeHash(nil) {
		return wrong("이 주소에 코드가 없습니다")
	}
	switch typ {
	case "proxy":
		if obs["implementation"] == zeroAddress {
			return wrong("EIP-1967 구현 슬롯이 비어 있습니다")
		}
	case "safe":
		if obs["owners"] == "" {
			return wrong("소유자가 없습니다")
		}
		if obs["threshold"] == "0" {
			return wrong("서명 임계값이 0입니다")
		}
	}
	return nil
}

// DelegateOutsideAllowList reports whether obs holds a delegate that the
// target's allowed_delegates does not list.
func DelegateOutsideAllowList(t Target, obs Observation) bool {
	d := obs["delegate"]
	return d != "" && !allowedDelegates(t)[normAddr(d)]
}

// ValidEnvName reports whether s looks like an environment variable name
// (letters, digits and underscore, not starting with a digit).
func ValidEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
