package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

const (
	addrA     = "0x1111111111111111111111111111111111111111"
	addrB     = "0x2222222222222222222222222222222222222222"
	walletHex = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
	implSlot  = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	adminSlot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)

// fakeNode answers JSON-RPC like a node would, from fixed values.
type fakeNode struct {
	chainID string            // eth_chainId result (hex)
	code    string            // eth_getCode result
	calls   map[string]string // eth_call data -> result
	slots   map[string]string // storage slot -> result
	block   string            // eth_getBlockByNumber result as raw JSON; "" means a block made just now
	raw     func(w http.ResponseWriter, r *http.Request)
}

func (n *fakeNode) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.raw != nil {
			n.raw(w, r)
			return
		}
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := "null"
		switch req.Method {
		case "eth_chainId":
			res = `"` + n.chainID + `"`
		case "eth_getCode":
			res = `"` + n.code + `"`
		case "eth_call":
			var c struct{ Data string }
			_ = json.Unmarshal(req.Params[0], &c)
			if v, ok := n.calls[c.Data]; ok {
				res = `"` + v + `"`
			}
		case "eth_getStorageAt":
			var slot string
			_ = json.Unmarshal(req.Params[1], &slot)
			if v, ok := n.slots[slot]; ok {
				res = `"` + v + `"`
			}
		case "eth_getBlockByNumber":
			res = n.block
			if res == "" {
				res = fmt.Sprintf(`{"timestamp":"0x%x"}`, time.Now().Unix())
			}
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + res + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func word(s string) string { return strings.Repeat("0", 64-len(s)) + s }

func addrWord(a string) string { return word(strings.ToLower(strings.TrimPrefix(a, "0x"))) }

func ownersReturn(addrs ...string) string {
	s := "0x" + word("20") + word(hex.EncodeToString([]byte{byte(len(addrs))}))
	for _, a := range addrs {
		s += addrWord(a)
	}
	return s
}

func clientFor(urls ...string) func(Target) *rpc.Client {
	return func(Target) *rpc.Client { return rpc.New(urls, nil) }
}

func observe(t *testing.T, opts map[string]any, urls ...string) (Observation, error) {
	t.Helper()
	o := newEVMObserver(clientFor(urls...), 0)
	return o.Observe(context.Background(), Target{Key: "w", Kind: "evm-wallet", Options: opts})
}

func mustObserve(t *testing.T, opts map[string]any, urls ...string) Observation {
	t.Helper()
	obs, err := observe(t, opts, urls...)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func opts(typ, addr string) map[string]any {
	return map[string]any{"chain_id": 1, "address": addr, "type": typ}
}

func sha(hexCode string) string {
	b, _ := hex.DecodeString(strings.TrimPrefix(hexCode, "0x"))
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestEVMKind(t *testing.T) {
	if NewEVMObserver(clientFor()).Kind() != "evm-wallet" {
		t.Fatal("kind")
	}
}

func TestDelegationParsed(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0xef0100" + "AbCdEf0123456789aBcDeF0123456789AbCdEf01"}
	obs := mustObserve(t, opts("eoa", walletHex), n.server(t).URL)
	if obs["delegate"] != "0xabcdef0123456789abcdef0123456789abcdef01" {
		t.Fatalf("delegate=%q", obs["delegate"])
	}
	if _, ok := obs["code_sha256"]; ok {
		t.Fatal("위임이면 code_sha256이 없어야 합니다")
	}
	if obs["chain_id"] != "1" {
		t.Fatalf("chain_id=%q", obs["chain_id"])
	}
	for _, k := range []string{"owners", "threshold", "master_copy", "implementation", "admin"} {
		if _, ok := obs[k]; ok {
			t.Fatalf("EOA에 %s가 있으면 안 됩니다", k)
		}
	}
}

func TestEOAPlain(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x"}
	obs := mustObserve(t, opts("eoa", walletHex), n.server(t).URL)
	v, ok := obs["delegate"]
	if !ok || v != "" {
		t.Fatalf("delegate는 빈 값이어야 합니다: %q %v", v, ok)
	}
	if _, ok := obs["code_sha256"]; ok {
		t.Fatal("code_sha256이 없어야 합니다")
	}
}

func TestEOAWithOtherCode(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x6080604052"}
	obs := mustObserve(t, opts("eoa", walletHex), n.server(t).URL)
	if v, ok := obs["delegate"]; !ok || v != "" {
		t.Fatalf("delegate=%q %v", v, ok)
	}
	if obs["code_sha256"] != sha("0x6080604052") {
		t.Fatalf("code_sha256=%q", obs["code_sha256"])
	}
}

func TestEOADelegationBadLength(t *testing.T) {
	for _, code := range []string{"0xef0100", "0xef0100aabb", "0xef0100" + strings.Repeat("11", 21)} {
		n := &fakeNode{chainID: "0x1", code: code}
		if _, err := observe(t, opts("eoa", walletHex), n.server(t).URL); err == nil {
			t.Fatalf("코드 %s는 오류여야 합니다", code)
		}
	}
}

func TestSafeFields(t *testing.T) {
	n := &fakeNode{
		chainID: "0x1",
		code:    "0x608060",
		calls: map[string]string{
			"0xa0e67e2b": ownersReturn(addrB, addrA, "0x0000000000000000000000000000000000000abc"),
			"0xe75235b8": "0x" + word("2"),
		},
		slots: map[string]string{
			"0x0": "0x" + addrWord("0xCAFE000000000000000000000000000000000001"),
		},
	}
	obs := mustObserve(t, opts("safe", walletHex), n.server(t).URL)
	wantOwners := "0x0000000000000000000000000000000000000abc," + addrA + "," + addrB
	if obs["owners"] != wantOwners {
		t.Fatalf("owners=%q", obs["owners"])
	}
	if obs["threshold"] != "2" {
		t.Fatalf("threshold=%q", obs["threshold"])
	}
	if obs["master_copy"] != "0xcafe000000000000000000000000000000000001" {
		t.Fatalf("master_copy=%q", obs["master_copy"])
	}
	if obs["code_sha256"] != sha("0x608060") {
		t.Fatalf("code_sha256=%q", obs["code_sha256"])
	}
	if _, ok := obs["delegate"]; ok {
		t.Fatal("Safe에 delegate가 있으면 안 됩니다")
	}
}

func TestObservationRecordsAddressAndType(t *testing.T) {
	for _, typ := range []string{"eoa", "safe", "proxy", "contract"} {
		n := &fakeNode{chainID: "0x1", code: "0x6080", calls: map[string]string{
			"0xa0e67e2b": ownersReturn(addrA), "0xe75235b8": "0x" + word("1"),
		}, slots: map[string]string{
			"0x0": "0x" + addrWord(addrA), implSlot: "0x" + addrWord(addrA), adminSlot: "0x" + addrWord(addrA),
		}}
		obs := mustObserve(t, opts(typ, walletHex), n.server(t).URL)
		if obs["address"] != strings.ToLower(walletHex) || obs["type"] != typ {
			t.Errorf("%s: address=%q type=%q", typ, obs["address"], obs["type"])
		}
	}
}

// Once slot 0 points at a contract without getOwners, the call reverts. What
// was read before that must survive.
func TestSafePartialKeepsWhatWasRead(t *testing.T) {
	newMC := "0xCAFE000000000000000000000000000000000001"
	cases := map[string]struct {
		calls map[string]string
		want  []string
		not   []string
	}{
		"getOwners reverts": {nil, []string{"code_sha256", "master_copy", "address", "type", "chain_id"}, []string{"owners", "threshold"}},
		"getThreshold reverts": {map[string]string{"0xa0e67e2b": ownersReturn(addrA)},
			[]string{"code_sha256", "master_copy", "owners"}, []string{"threshold"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := &fakeNode{chainID: "0x1", code: "0x6080", calls: c.calls, slots: map[string]string{"0x0": "0x" + addrWord(newMC)}}
			obs, err := observe(t, opts("safe", walletHex), n.server(t).URL)
			var pe PartialError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want a PartialError", err)
			}
			if obs != nil {
				t.Errorf("the returned observation must be nil: %v", obs)
			}
			if pe.Obs["master_copy"] != strings.ToLower(newMC) {
				t.Errorf("master_copy = %q", pe.Obs["master_copy"])
			}
			for _, f := range c.want {
				if _, ok := pe.Obs[f]; !ok {
					t.Errorf("%s was read but is missing: %v", f, pe.Obs)
				}
			}
			for _, f := range c.not {
				if _, ok := pe.Obs[f]; ok {
					t.Errorf("%s was not read but is present: %v", f, pe.Obs)
				}
			}
		})
	}
}

func TestProxyPartialKeepsImplementation(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x60", slots: map[string]string{
		implSlot: "0x" + addrWord(addrA), adminSlot: "0x1234",
	}}
	_, err := observe(t, opts("proxy", walletHex), n.server(t).URL)
	var pe PartialError
	if !errors.As(err, &pe) || pe.Obs["implementation"] != addrA {
		t.Fatalf("err = %#v", err)
	}
	if _, ok := pe.Obs["admin"]; ok {
		t.Errorf("admin was not read: %v", pe.Obs)
	}
}

// Failing to read the code still leaves the fields known from the config, so
// an edited address is seen even when the RPC is down.
func TestCodeReadFailureKeepsConfigFields(t *testing.T) {
	n := &fakeNode{chainID: "0x1", raw: func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) }}
	_, err := observe(t, opts("eoa", walletHex), n.server(t).URL)
	var pe PartialError
	if !errors.As(err, &pe) || pe.Obs["address"] != strings.ToLower(walletHex) || pe.Obs["type"] != "eoa" {
		t.Fatalf("err = %#v", err)
	}
}

func TestSafeEmptyCallIsError(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x", calls: map[string]string{
		"0xa0e67e2b": "0x", "0xe75235b8": "0x",
	}}
	if _, err := observe(t, opts("safe", walletHex), n.server(t).URL); err == nil {
		t.Fatal("eth_call이 0x면 오류여야 합니다")
	}
}

func TestSafeMalformedABI(t *testing.T) {
	cases := map[string]string{
		"짧음":           "0x" + word("20"),
		"오프셋 초과":       "0x" + word("1000") + word("1"),
		"오프셋 거대":       "0x" + strings.Repeat("ff", 32) + word("1"),
		"길이 초과":        "0x" + word("20") + word("5") + addrWord(addrA),
		"길이 거대":        "0x" + word("20") + strings.Repeat("ff", 32),
		"주소 상위 바이트 이상": "0x" + word("20") + word("1") + "ff" + word("1")[2:],
		"32바이트 정렬 아님":  "0x" + word("20") + word("1") + addrWord(addrA)[:60],
	}
	for name, ret := range cases {
		n := &fakeNode{chainID: "0x1", code: "0x60", calls: map[string]string{
			"0xa0e67e2b": ret, "0xe75235b8": "0x" + word("1"),
		}, slots: map[string]string{"0x0": "0x" + addrWord(addrA)}}
		if _, err := observe(t, opts("safe", walletHex), n.server(t).URL); err == nil {
			t.Fatalf("%s: 오류여야 합니다", name)
		}
	}
}

func TestSafeBadThreshold(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x60", calls: map[string]string{
		"0xa0e67e2b": ownersReturn(addrA), "0xe75235b8": "0x01",
	}, slots: map[string]string{"0x0": "0x" + addrWord(addrA)}}
	if _, err := observe(t, opts("safe", walletHex), n.server(t).URL); err == nil {
		t.Fatal("32바이트가 아닌 threshold는 오류여야 합니다")
	}
}

func TestProxySlots(t *testing.T) {
	n := &fakeNode{
		chainID: "0x1",
		code:    "0x363d3d37",
		slots: map[string]string{
			implSlot:  "0x" + addrWord("0xAAAA000000000000000000000000000000000001"),
			adminSlot: "0x" + addrWord("0xBBBB000000000000000000000000000000000002"),
		},
	}
	obs := mustObserve(t, opts("proxy", walletHex), n.server(t).URL)
	if obs["implementation"] != "0xaaaa000000000000000000000000000000000001" {
		t.Fatalf("implementation=%q", obs["implementation"])
	}
	if obs["admin"] != "0xbbbb000000000000000000000000000000000002" {
		t.Fatalf("admin=%q", obs["admin"])
	}
	if obs["code_sha256"] != sha("0x363d3d37") {
		t.Fatalf("code_sha256=%q", obs["code_sha256"])
	}
}

func TestProxyBadSlotLength(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x60", slots: map[string]string{
		implSlot: "0x1234", adminSlot: "0x" + addrWord(addrA),
	}}
	if _, err := observe(t, opts("proxy", walletHex), n.server(t).URL); err == nil {
		t.Fatal("32바이트가 아닌 슬롯 값은 오류여야 합니다")
	}
}

func TestContract(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x6080"}
	obs := mustObserve(t, opts("contract", walletHex), n.server(t).URL)
	if obs["code_sha256"] != sha("0x6080") || obs["chain_id"] != "1" {
		t.Fatalf("%v", obs)
	}
	if len(obs) != 4 {
		t.Fatalf("contract는 address, type, chain_id, code_sha256만: %v", obs)
	}
}

func TestBadResponses(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"HTTP 500": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) },
		"HTML 본문":  func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>no</html>")) },
		"JSON-RPC 오류": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`))
		},
		"16진수 아님": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"zzz"}`))
		},
	}
	for name, h := range cases {
		n := &fakeNode{raw: h}
		if _, err := observe(t, opts("eoa", walletHex), n.server(t).URL); err == nil {
			t.Fatalf("%s: 오류여야 합니다", name)
		}
	}
	// 설정과 다른 체인 ID
	n := &fakeNode{chainID: "0x89", code: "0x"}
	if _, err := observe(t, opts("eoa", walletHex), n.server(t).URL); err == nil {
		t.Fatal("chain_id 불일치는 오류여야 합니다")
	}
}

func TestChainIDMismatchOnSecondURL(t *testing.T) {
	a := &fakeNode{chainID: "0x1", code: "0x"}
	b := &fakeNode{chainID: "0x89", code: "0x"}
	_, err := observe(t, opts("eoa", walletHex), a.server(t).URL, b.server(t).URL)
	if err == nil {
		t.Fatal("두 번째 RPC의 chain_id 불일치도 오류여야 합니다")
	}
	if !strings.Contains(err.Error(), "RPC 2") {
		t.Fatalf("위치로 가리켜야 합니다: %v", err)
	}
}

func TestDisagreement(t *testing.T) {
	a := &fakeNode{chainID: "0x1", code: "0x"}
	b := &fakeNode{chainID: "0x1", code: "0x6080"}
	_, err := observe(t, opts("eoa", walletHex), a.server(t).URL, b.server(t).URL)
	if !errors.Is(err, rpc.ErrDisagree) {
		t.Fatalf("ErrDisagree여야 합니다: %v", err)
	}
}

func TestDisagreementSettlesOnRetry(t *testing.T) {
	a := &fakeNode{chainID: "0x1", code: "0x"}
	calls := 0
	b := &fakeNode{raw: func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Method string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := `"0x1"`
		if req.Method == "eth_getCode" {
			calls++
			if calls == 1 {
				res = `"0x6080"`
			} else {
				res = `"0x"`
			}
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + res + `}`))
	}}
	o := opts("eoa", walletHex)
	o["max_block_age"] = "0" // b answers every other method with a hex string
	obs, err := observe(t, o, a.server(t).URL, b.server(t).URL)
	if err != nil {
		t.Fatal(err)
	}
	if obs["delegate"] != "" {
		t.Fatalf("%v", obs)
	}
}

func TestOptionErrors(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x"}
	url := n.server(t).URL
	bad := map[string]map[string]any{
		"chain_id 없음":     {"address": walletHex, "type": "eoa"},
		"chain_id 실수":     {"chain_id": 1.5, "address": walletHex, "type": "eoa"},
		"chain_id 불리언":    {"chain_id": true, "address": walletHex, "type": "eoa"},
		"chain_id 문자":     {"chain_id": "abc", "address": walletHex, "type": "eoa"},
		"chain_id 음수":     {"chain_id": -1, "address": walletHex, "type": "eoa"},
		"address 없음":      {"chain_id": 1, "type": "eoa"},
		"address 짧음":      {"chain_id": 1, "address": "0x1234", "type": "eoa"},
		"address 16진수 아님": {"chain_id": 1, "address": "0x" + strings.Repeat("zz", 20), "type": "eoa"},
		"address 숫자":      {"chain_id": 1, "address": 5, "type": "eoa"},
		"type 없음":         {"chain_id": 1, "address": walletHex},
		"type 모름":         {"chain_id": 1, "address": walletHex, "type": "nft"},
	}
	for name, o := range bad {
		if _, err := observe(t, o, url); err == nil {
			t.Fatalf("%s: 오류여야 합니다", name)
		}
	}
}

func TestChainIDForms(t *testing.T) {
	n := &fakeNode{chainID: "0x89", code: "0x"}
	url := n.server(t).URL
	for _, v := range []any{137, int64(137), uint64(137), "137", "0x89", "0X89"} {
		o := opts("eoa", walletHex)
		o["chain_id"] = v
		obs, err := observe(t, o, url)
		if err != nil {
			t.Fatalf("%T %v: %v", v, v, err)
		}
		if obs["chain_id"] != "137" {
			t.Fatalf("chain_id=%q", obs["chain_id"])
		}
	}
}

func TestAddressWithoutPrefixAndCase(t *testing.T) {
	// The handler below answers only the methods this test is about.
	noBlockCheck := func(m map[string]any) map[string]any {
		m["max_block_age"] = "0"
		return m
	}
	var gotTo string
	n := &fakeNode{raw: func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string
			Params []json.RawMessage
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := `"0x1"`
		if req.Method == "eth_getCode" {
			_ = json.Unmarshal(req.Params[0], &gotTo)
			res = `"0x"`
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + res + `}`))
	}}
	mustObserve(t, noBlockCheck(opts("eoa", walletHex)), n.server(t).URL)
	if gotTo != strings.ToLower(walletHex) {
		t.Fatalf("to=%q", gotTo)
	}
}

func TestNoClientURLs(t *testing.T) {
	if _, err := observe(t, opts("eoa", walletHex)); err == nil {
		t.Fatal("URL이 없으면 오류여야 합니다")
	}
}

func TestEnvClient(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x"}
	a, b := n.server(t), n.server(t)
	t.Setenv("ADK_TEST_RPC_A", a.URL+"/key-AAA")
	t.Setenv("ADK_TEST_RPC_B", b.URL+"/key-BBB")
	o := opts("eoa", walletHex)
	o["rpc_url_env"] = "ADK_TEST_RPC_A, ADK_TEST_RPC_B"
	tg := Target{Key: "w", Kind: "evm-wallet", Options: o}
	obs, err := NewEVMObserver(NewEnvClient).Observe(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if obs["chain_id"] != "1" {
		t.Fatalf("%v", obs)
	}
}

func TestEnvClientErrors(t *testing.T) {
	t.Setenv("ADK_TEST_EMPTY", "")
	t.Setenv("ADK_TEST_OK", "http://127.0.0.1:1/key-SECRET")
	cases := map[string]struct {
		opt    any
		secret string
	}{
		"없는 변수":  {"ADK_TEST_NOPE", "ADK_TEST_NOPE"},
		"빈 변수":   {"ADK_TEST_OK,ADK_TEST_EMPTY", "ADK_TEST_EMPTY"},
		"옵션 없음":  {nil, ""},
		"문자열 아님": {5, ""},
	}
	for name, c := range cases {
		o := opts("eoa", walletHex)
		if c.opt != nil {
			o["rpc_url_env"] = c.opt
		}
		tg := Target{Key: "w", Kind: "evm-wallet", Options: o}
		_, err := NewEVMObserver(NewEnvClient).Observe(context.Background(), tg)
		if err == nil {
			t.Fatalf("%s: 오류여야 합니다", name)
		}
		if c.secret != "" && !strings.Contains(err.Error(), c.secret) {
			t.Fatalf("%s: 변수 이름이 있어야 합니다: %v", name, err)
		}
		if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("%s: 오류에 URL이 있습니다: %v", name, err)
		}
	}
}

func TestEVMErrorsHideURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL + "/v2/KEYKEY"
	srv.Close()
	_, err := observe(t, opts("eoa", walletHex), u)
	if err == nil {
		t.Fatal("오류여야 합니다")
	}
	if strings.Contains(err.Error(), "KEYKEY") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("오류에 URL이 있습니다: %v", err)
	}
}

func TestSlotNonzeroHighBytesIsError(t *testing.T) {
	dirty := "0x" + "ff" + strings.Repeat("00", 11) + strings.TrimPrefix(addrA, "0x")
	proxy := &fakeNode{chainID: "0x1", code: "0x60", slots: map[string]string{
		implSlot: dirty, adminSlot: "0x" + addrWord(addrB),
	}}
	if _, err := observe(t, opts("proxy", walletHex), proxy.server(t).URL); err == nil {
		t.Fatal("proxy: 슬롯 앞 12바이트가 0이 아니면 오류여야 합니다")
	}
	proxy.slots = map[string]string{implSlot: "0x" + addrWord(addrA), adminSlot: dirty}
	if _, err := observe(t, opts("proxy", walletHex), proxy.server(t).URL); err == nil {
		t.Fatal("proxy admin: 오류여야 합니다")
	}
	safe := &fakeNode{chainID: "0x1", code: "0x60", calls: map[string]string{
		"0xa0e67e2b": ownersReturn(addrA), "0xe75235b8": "0x" + word("1"),
	}, slots: map[string]string{"0x0": dirty}}
	if _, err := observe(t, opts("safe", walletHex), safe.server(t).URL); err == nil {
		t.Fatal("safe master_copy: 오류여야 합니다")
	}
}

func TestSingleEndpoint(t *testing.T) {
	cases := []struct {
		raw  any
		want bool
	}{
		{"A", true}, {"A,B", false}, {"A, B ,C", false}, {"", true}, {nil, true}, {" A ", true},
	}
	for _, c := range cases {
		tg := Target{Kind: "evm-wallet", Options: map[string]any{"rpc_url_env": c.raw}}
		if got := SingleEndpoint(tg); got != c.want {
			t.Errorf("%v: got %v", c.raw, got)
		}
	}
}

func TestNewEnvClientRejectsAddressesAsNames(t *testing.T) {
	const secret = "https://node.example/v2/SECRETKEY123"
	for _, raw := range []string{secret, "OK_NAME," + secret, "A B", "1ABC", "A-B"} {
		c := NewEnvClient(Target{Key: "w", Options: map[string]any{"rpc_url_env": raw}})
		_, err := c.Call(context.Background(), "eth_chainId", nil)
		if err == nil || strings.Contains(err.Error(), "SECRETKEY123") || strings.Contains(err.Error(), "node.example") || !strings.Contains(err.Error(), "w") {
			t.Errorf("%q: err = %v", raw, err)
		}
	}
}
