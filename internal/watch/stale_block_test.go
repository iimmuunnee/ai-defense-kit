package watch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func blockAt(ts time.Time) string { return fmt.Sprintf(`{"timestamp":"0x%x"}`, ts.Unix()) }

func observeAt(t *testing.T, opts map[string]any, urls ...string) (Observation, error) {
	t.Helper()
	o := newEVMObserver(clientFor(urls...), 0).(*evmObserver)
	o.now = func() time.Time { return testNow }
	return o.Observe(context.Background(), Target{Key: "w", Kind: "evm-wallet", Options: opts})
}

func withOpt(m map[string]any, k string, v any) map[string]any {
	m[k] = v
	return m
}

// The document is what readers rely on: limits must be stated, and what has
// not been proven must stay marked as not proven.
func TestWatchDocs(t *testing.T) {
	s := readText(t, "../../docs/watch.md")
	for _, want := range []string{
		"이 훈련으로 확인하지 못한 것", "메인넷이나 테스트넷에서는 돌리지 않았습니다",
		"Safe와 프록시, 컨트랙트 대상은 로컬 체인에서 돌리지 않았습니다",
		"WA-006", "WA-007", "`--expect", "`--allow-env-proxy`", "`max_block_age`", "adk-watch-events.jsonl",
		"처음 상태가 정상", "모듈", "가드", "폴백", "비콘", "EIP-1967 이전", "UUPS", "ProxyAdmin",
		"업그레이드되어도", "변조", "SARIF", "실제 체인에서 측정하지 않았습니다",
		"멈춘 것으로 보이는 노드에서 읽은 값입니다", "기준값보다 오래된", "`stale_targets`", "`confidence`",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
	for _, bad := range []string{"막는다", "안전", "방어한다", "`WA-003` | 코드, 구현, 로직", "두 번 물어도 서로 다름"} {
		if strings.Contains(s, bad) {
			t.Errorf("docs/watch.md contains %q", bad)
		}
	}
}

func TestStaleBlockIsPartial(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(-16 * time.Minute))}
	_, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL)
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want a PartialError", err)
	}
	if !strings.Contains(err.Error(), "RPC 1") || !strings.Contains(err.Error(), "블록") {
		t.Errorf("err = %v", err)
	}
	if v, ok := pe.Obs["delegate"]; !ok || v != "" {
		t.Errorf("the fields read before the age check must survive: %v", pe.Obs)
	}
}

func TestFreshBlockAndBoundary(t *testing.T) {
	for name, age := range map[string]time.Duration{"fresh": time.Minute, "at the limit": 15 * time.Minute} {
		n := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(-age))}
		if _, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A block far in the future is no more believable than an old one.
func TestFutureBlockIsNotFresh(t *testing.T) {
	n := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(time.Hour))}
	if _, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL); err == nil {
		t.Fatal("expected an error")
	}
}

func TestOneStaleOfTwoNamesItsPosition(t *testing.T) {
	a := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow)}
	b := &fakeNode{chainID: "0x1", code: "0x", block: blockAt(testNow.Add(-time.Hour))}
	_, err := observeAt(t, opts("eoa", walletHex), a.server(t).URL, b.server(t).URL)
	if err == nil || !strings.Contains(err.Error(), "RPC 2") {
		t.Fatalf("err = %v", err)
	}
}

func TestMaxBlockAgeOption(t *testing.T) {
	stale := blockAt(testNow.Add(-time.Hour))
	n := &fakeNode{chainID: "0x1", code: "0x", block: stale}
	url := n.server(t).URL
	for _, v := range []any{"0", 0, "2h"} {
		if _, err := observeAt(t, withOpt(opts("eoa", walletHex), "max_block_age", v), url); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	if _, err := observeAt(t, withOpt(opts("eoa", walletHex), "max_block_age", "30m"), url); err == nil {
		t.Error("30m: expected stale")
	}
	// Disabled means not read at all: a node that cannot answer it is fine.
	nb := &fakeNode{chainID: "0x1", code: "0x", block: "null"}
	if _, err := observeAt(t, withOpt(opts("eoa", walletHex), "max_block_age", "0"), nb.server(t).URL); err != nil {
		t.Errorf("disabled: %v", err)
	}
}

func TestBadBlockAnswersAreUnverified(t *testing.T) {
	for _, res := range []string{"null", `{}`, `{"timestamp":"zz"}`, `{"timestamp":5}`, `"0x1"`, `{"timestamp":"0xffffffffffffffffffff"}`} {
		n := &fakeNode{chainID: "0x1", code: "0x", block: res}
		_, err := observeAt(t, opts("eoa", walletHex), n.server(t).URL)
		var pe PartialError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), "RPC 1") {
			t.Errorf("%s: err = %v", res, err)
		}
	}
}

func TestLoadConfigChecksOptions(t *testing.T) {
	base := "targets:\n  - key: hot\n    kind: evm-wallet\n    options:\n"
	cases := map[string]struct{ body, want string }{
		"unknown key":       {"      allowed_delegate: [\"0x1\"]\n", "allowed_delegate"},
		"address as number": {"      address: 0x10\n", "따옴표"},
		"allowed as number": {"      allowed_delegates: [0x10]\n", "따옴표"},
		"bad age":           {"      max_block_age: \"soon\"\n", "max_block_age"},
		"negative age":      {"      max_block_age: \"-5m\"\n", "max_block_age"},
		"age without unit":  {"      max_block_age: 15\n", "max_block_age"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeFile(t, "w.yaml", base+c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "hot") {
				t.Errorf("err = %v", err)
			}
		})
	}
	good := base + "      chain_id: 1\n      address: \"0x1\"\n      type: eoa\n      rpc_url_env: A\n      allowed_delegates: [\"0x2\"]\n      max_block_age: \"0\"\n"
	if _, err := LoadConfig(writeFile(t, "w.yaml", good)); err != nil {
		t.Errorf("all known options: %v", err)
	}
}

func TestParseAddressNumberHasAClearMessage(t *testing.T) {
	_, err := parseAddress(16)
	if err == nil || !strings.Contains(err.Error(), "따옴표") {
		t.Errorf("err = %v", err)
	}
}

func TestSingleEndpointComparesResolvedAddresses(t *testing.T) {
	t.Setenv("ADK_T_A", "https://one.example/k")
	t.Setenv("ADK_T_B", " https://one.example/k ")
	t.Setenv("ADK_T_C", "https://two.example/k")
	cases := []struct {
		raw  string
		want bool
	}{
		{"ADK_T_A", true}, {"ADK_T_A,ADK_T_A", true}, {"ADK_T_A,ADK_T_B", true}, {"ADK_T_A,ADK_T_C", false},
		{"ADK_T_UNSET_1,ADK_T_UNSET_2", false},
	}
	for _, c := range cases {
		tg := Target{Kind: "evm-wallet", Options: map[string]any{"rpc_url_env": c.raw}}
		if got := SingleEndpoint(tg); got != c.want {
			t.Errorf("%s: got %v", c.raw, got)
		}
	}
	// A later kind with no RPC at all does not get the note.
	if SingleEndpoint(Target{Kind: "other"}) {
		t.Error("the note is for evm-wallet only")
	}
}

func TestCheckInitial(t *testing.T) {
	empty := codeHash(nil)
	zero := "0x" + strings.Repeat("0", 40)
	cases := []struct {
		name, typ string
		obs       Observation
		bad       bool
	}{
		{"eoa", "eoa", Observation{"delegate": ""}, false},
		{"contract ok", "contract", Observation{"code_sha256": "ab"}, false},
		{"contract empty", "contract", Observation{"code_sha256": empty}, true},
		{"proxy ok without admin", "proxy", Observation{"code_sha256": "ab", "implementation": addrA, "admin": zero}, false},
		{"proxy empty code", "proxy", Observation{"code_sha256": empty, "implementation": addrA}, true},
		{"proxy zero implementation", "proxy", Observation{"code_sha256": "ab", "implementation": zero}, true},
		{"safe ok", "safe", Observation{"code_sha256": "ab", "owners": addrA, "threshold": "1"}, false},
		{"safe empty code", "safe", Observation{"code_sha256": empty, "owners": addrA, "threshold": "1"}, true},
		{"safe no owners", "safe", Observation{"code_sha256": "ab", "owners": "", "threshold": "1"}, true},
		{"safe threshold 0", "safe", Observation{"code_sha256": "ab", "owners": addrA, "threshold": "0"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.obs["type"] = c.typ
			err := CheckInitial(Target{Key: "the-key", Kind: "evm-wallet"}, c.obs)
			if (err != nil) != c.bad {
				t.Fatalf("err = %v", err)
			}
			if err != nil && (!strings.Contains(err.Error(), "the-key") || !strings.Contains(err.Error(), "type")) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestDelegateOutsideAllowList(t *testing.T) {
	tg := Target{Key: "w", Kind: "evm-wallet", Options: map[string]any{"allowed_delegates": []any{strings.ToUpper(delA[2:])}}}
	for obs, want := range map[string]bool{"": false, delA: false, delB: true} {
		if got := DelegateOutsideAllowList(tg, Observation{"delegate": obs}); got != want {
			t.Errorf("%q: got %v", obs, got)
		}
	}
	if !DelegateOutsideAllowList(Target{Kind: "evm-wallet"}, Observation{"delegate": delA}) {
		t.Error("no allow list at all: outside")
	}
	if DelegateOutsideAllowList(Target{Kind: "evm-wallet"}, Observation{"code_sha256": "x"}) {
		t.Error("no delegate field")
	}
}
