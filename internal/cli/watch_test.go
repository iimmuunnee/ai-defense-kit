package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testWallet  = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"
	testWallet2 = "0x9999999999999999999999999999999999999999"
	testDelA    = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDelB    = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeChain is an in-process node that answers eth_chainId and eth_getCode
// for one externally owned account. Tests change the code it returns.
type fakeChain struct {
	mu     sync.Mutex
	code   string
	status int // when non-zero, every request gets this HTTP status
	hits   int
	onHit  func() // called before each request is answered
	// calls and slots answer eth_call and eth_getStorageAt. A call not listed
	// reverts (a JSON-RPC error); a slot not listed reads as all zero.
	calls    map[string]string
	slots    map[string]string
	blockAge time.Duration // how old the latest block is
	srv      *httptest.Server
}

func newFakeChain(t *testing.T) *fakeChain {
	t.Helper()
	c := &fakeChain{code: "0x"}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f := c.hook(); f != nil {
			f()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.hits++
		if c.status != 0 {
			w.WriteHeader(c.status)
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
			res = `"0x1"`
		case "eth_getCode":
			res = `"` + c.code + `"`
		case "eth_call":
			var call struct{ Data string }
			_ = json.Unmarshal(req.Params[0], &call)
			v, ok := c.calls[call.Data]
			if !ok {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}`))
				return
			}
			res = `"` + v + `"`
		case "eth_getStorageAt":
			var slot string
			_ = json.Unmarshal(req.Params[1], &slot)
			v, ok := c.slots[slot]
			if !ok {
				v = "0x" + strings.Repeat("0", 64)
			}
			res = `"` + v + `"`
		case "eth_getBlockByNumber":
			res = fmt.Sprintf(`{"number":"0x10","timestamp":"0x%x"}`, time.Now().Add(-c.blockAge).Unix())
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + res + `}`))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeChain) hook() func()     { c.mu.Lock(); defer c.mu.Unlock(); return c.onHit }
func (c *fakeChain) setHook(f func()) { c.mu.Lock(); c.onHit = f; c.mu.Unlock() }
func (c *fakeChain) setCode(s string) { c.mu.Lock(); c.code = s; c.mu.Unlock() }
func (c *fakeChain) setStatus(s int)  { c.mu.Lock(); c.status = s; c.mu.Unlock() }

func delegationCode(addr string) string { return "0xef0100" + strings.TrimPrefix(addr, "0x") }

type wTarget struct {
	key, addr, envs string
	allowed         []string
	typ             string // "" means eoa
	extra           string // more lines under options, already indented
}

type wsp struct {
	t                  *testing.T
	dir                string
	cfg, base, history string
}

func newWsp(t *testing.T, targets ...wTarget) *wsp {
	t.Helper()
	dir := t.TempDir()
	w := &wsp{t: t, dir: dir, cfg: filepath.Join(dir, "adk-watch.yaml"),
		base: filepath.Join(dir, "adk-watch-baseline.json"), history: filepath.Join(dir, "adk-watch-history.jsonl")}
	w.writeCfg(targets...)
	return w
}

func (w *wsp) writeCfg(targets ...wTarget) {
	w.t.Helper()
	var b strings.Builder
	b.WriteString("targets:\n")
	if len(targets) == 0 {
		b.Reset()
		b.WriteString("targets: []\n")
	}
	for _, tg := range targets {
		typ := tg.typ
		if typ == "" {
			typ = "eoa"
		}
		fmt.Fprintf(&b, "  - key: %s\n    kind: evm-wallet\n    options:\n      chain_id: 1\n      address: \"%s\"\n      type: %s\n      rpc_url_env: \"%s\"\n",
			tg.key, tg.addr, typ, tg.envs)
		b.WriteString(tg.extra)
		if len(tg.allowed) > 0 {
			b.WriteString("      allowed_delegates:\n")
			for _, a := range tg.allowed {
				fmt.Fprintf(&b, "        - \"%s\"\n", a)
			}
		}
	}
	if err := os.WriteFile(w.cfg, []byte(b.String()), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

// run runs "adk watch <sub> ..." with the workspace's file paths.
func (w *wsp) run(sub string, extra ...string) (int, string, string) {
	w.t.Helper()
	return w.runCtx(context.Background(), sub, extra...)
}

func (w *wsp) runCtx(ctx context.Context, sub string, extra ...string) (int, string, string) {
	w.t.Helper()
	args := append([]string{"watch", sub, "--config", w.cfg, "--baseline", w.base}, extra...)
	var o, e bytes.Buffer
	code := Run(ctx, args, &o, &e)
	return code, o.String(), e.String()
}

// oneWallet sets up a wallet read through two endpoints that are the same fake chain.
func oneWallet(t *testing.T) (*wsp, *fakeChain) {
	t.Helper()
	c := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", c.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", c.srv.URL+"/b")
	return newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"}), c
}

func mustInit(t *testing.T, w *wsp) string {
	t.Helper()
	code, out, errs := w.run("init")
	if code != 0 {
		t.Fatalf("init = %d\nstdout: %s\nstderr: %s", code, out, errs)
	}
	return out
}

var sha64 = regexp.MustCompile(`[0-9a-f]{64}`)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestWatchInitThenCheck(t *testing.T) {
	w, chain := oneWallet(t)
	out := mustInit(t, w)
	sum := sha64.FindString(out)
	if sum == "" || !strings.Contains(out, "따로") {
		t.Fatalf("init must print the baseline SHA-256 and say to keep it elsewhere: %q", out)
	}
	if got, _ := wFileSHA(w.base); got != sum {
		t.Errorf("printed %s, file is %s", sum, got)
	}

	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("unchanged check = %d\n%s\n%s", code, out, errs)
	}

	chain.setCode(delegationCode(testDelA))
	code, out, _ := w.run("check")
	if code != 1 || !strings.Contains(out, "WA-001") {
		t.Fatalf("delegation check = %d\n%s", code, out)
	}

	chain.setCode("0x")
	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("removed delegation check = %d\n%s\n%s", code, out, errs)
	}
}

func wFileSHA(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}

func TestWatchAllowedDelegateIsInfo(t *testing.T) {
	c := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", c.srv.URL)
	t.Setenv("ADK_T_RPC_B", c.srv.URL)
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B", allowed: []string{strings.ToUpper(testDelA[:2]) + strings.ToUpper(testDelA[2:])}})
	mustInit(t, w)
	c.setCode(delegationCode(testDelA))
	code, out, _ := w.run("check")
	if code != 0 || !strings.Contains(out, "WA-005") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestWatchInitRefusesToOverwrite(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	before := readFile(t, w.base)
	code, _, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "이미") || !strings.Contains(errs, "accept") {
		t.Fatalf("code=%d stderr=%s", code, errs)
	}
	if readFile(t, w.base) != before {
		t.Error("the baseline changed")
	}
}

func TestWatchInitWritesNothingWhenATargetCannotBeRead(t *testing.T) {
	good := newFakeChain(t)
	bad := newFakeChain(t)
	badURL := bad.srv.URL
	bad.srv.Close()
	t.Setenv("ADK_T_GOOD", good.srv.URL)
	t.Setenv("ADK_T_BAD", badURL)
	w := newWsp(t,
		wTarget{key: "a", addr: testWallet, envs: "ADK_T_GOOD"},
		wTarget{key: "b", addr: testWallet2, envs: "ADK_T_BAD"})
	code, _, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "b") {
		t.Fatalf("code=%d stderr=%s", code, errs)
	}
	if fileExists(w.base) {
		t.Error("a baseline was written")
	}
}

func TestWatchNoTargetsIsAnError(t *testing.T) {
	w := newWsp(t)
	for _, sub := range []string{"init", "check"} {
		if code, _, errs := w.run(sub); code != 2 || !strings.Contains(errs, "대상") {
			t.Errorf("%s: code=%d stderr=%s", sub, code, errs)
		}
	}
	if fileExists(w.base) {
		t.Error("a baseline was written")
	}
}

func TestWatchUnverified(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.srv.Close()

	code, out, errs := w.run("check")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	for _, s := range []string{"확인 못 함", "hot"} {
		if !strings.Contains(out, s) || !strings.Contains(errs, s) {
			t.Errorf("%q missing\nstdout: %s\nstderr: %s", s, out, errs)
		}
	}
	// JSON lists the target and the reason too.
	_, js, _ := w.run("check", "--format", "json")
	var rep struct {
		Checks []struct{ Name, Status, Error string }
	}
	if err := json.Unmarshal([]byte(js), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, js)
	}
	found := false
	for _, c := range rep.Checks {
		if strings.Contains(c.Name, "hot") && c.Status == "failed" && strings.Contains(c.Error, "확인 못 함") && strings.Contains(c.Error, "연결하지 못했습니다") {
			found = true
		}
	}
	if !found {
		t.Errorf("checks = %+v", rep.Checks)
	}
}

// With a finding the exit is 1, and the target that could not be read is still listed.
func TestWatchUnverifiedIsListedWhenExitIsOne(t *testing.T) {
	a, b := newFakeChain(t), newFakeChain(t)
	t.Setenv("ADK_T_A", a.srv.URL)
	t.Setenv("ADK_T_B", b.srv.URL)
	w := newWsp(t,
		wTarget{key: "up", addr: testWallet, envs: "ADK_T_A"},
		wTarget{key: "down", addr: testWallet2, envs: "ADK_T_B"})
	mustInit(t, w)
	a.setCode(delegationCode(testDelA))
	b.srv.Close()
	for _, f := range []string{"md", "json"} {
		code, out, _ := w.run("check", "--format", f)
		if code != 1 || !strings.Contains(out, "WA-001") || !strings.Contains(out, "down") || !strings.Contains(out, "확인 못 함") {
			t.Errorf("%s: code=%d\n%s", f, code, out)
		}
	}
}

func TestWatchDisagreementIsWA004(t *testing.T) {
	a, b := newFakeChain(t), newFakeChain(t)
	t.Setenv("ADK_T_A", a.srv.URL)
	t.Setenv("ADK_T_B", b.srv.URL)
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_A,ADK_T_B"})
	mustInit(t, w)
	b.setCode(delegationCode(testDelB)) // the second endpoint now lies
	code, out, _ := w.run("check")
	if code != 1 || !strings.Contains(out, "WA-004") || !strings.Contains(out, "확인 못 함") {
		t.Fatalf("code=%d\n%s", code, out)
	}
}

func TestWatchNoBaseline(t *testing.T) {
	w, _ := oneWallet(t)
	code, out, errs := w.run("check")
	if code != 2 || !strings.Contains(errs, "기준값") || out != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

func TestWatchBrokenBaselineAndPin(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	sum, _ := wFileSHA(w.base)

	if code, _, errs := w.run("check", "--baseline-sha256", sum); code != 0 {
		t.Fatalf("matching pin: code=%d %s", code, errs)
	}
	code, _, errs := w.run("check", "--baseline-sha256", strings.Repeat("0", 64))
	if code != 2 || !strings.Contains(errs, "SHA-256") {
		t.Fatalf("wrong pin: code=%d %s", code, errs)
	}
	if err := os.WriteFile(w.base, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w.run("check"); code != 2 || !strings.Contains(errs, "기준값") {
		t.Fatalf("corrupt: code=%d %s", code, errs)
	}
}

func TestWatchTargetMissingFromBaselineIsNotClean(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	w.writeCfg(
		wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"},
		wTarget{key: "extra", addr: testWallet2, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	code, out, _ := w.run("check")
	if code != 2 || !strings.Contains(out, "extra") {
		t.Fatalf("new target: code=%d\n%s", code, out)
	}
	w.writeCfg(wTarget{key: "other", addr: testWallet2, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	code, out, _ = w.run("check")
	if code != 2 || !strings.Contains(out, "hot") {
		t.Fatalf("removed target: code=%d\n%s", code, out)
	}
}

func TestWatchAccept(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	before := readFile(t, w.base)

	for _, args := range [][]string{{"hot"}, {"hot", "--note", ""}, {"hot", "--note", "   "}} {
		code, _, errs := w.run("accept", args...)
		if code != 2 || !strings.Contains(errs, "--note") {
			t.Errorf("%v: code=%d %s", args, code, errs)
		}
	}
	if readFile(t, w.base) != before || fileExists(w.history) {
		t.Fatal("a refused accept changed something")
	}
	for _, args := range [][]string{{"nope", "--note", "x"}, {"--note", "x"}} {
		code, _, errs := w.run("accept", args...)
		if code != 2 || errs == "" {
			t.Errorf("%v: code=%d %s", args, code, errs)
		}
	}
	if readFile(t, w.base) != before || fileExists(w.history) {
		t.Fatal("a refused accept changed something")
	}

	code, out, errs := w.run("accept", "hot", "--note", "새 지갑 모듈 적용 승인")
	if code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
	newSum, _ := wFileSHA(w.base)
	if got := sha64.FindString(out); got != newSum {
		t.Errorf("printed %q, file is %s", got, newSum)
	}
	oldSum := sha256Hex([]byte(before))
	lines := strings.Split(strings.TrimRight(readFile(t, w.history), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("history = %q", lines)
	}
	var raw map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &raw)
	for _, k := range []string{"time", "os_user", "key", "note", "old_hash", "new_hash"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("history entry lacks %q: %s", k, lines[0])
		}
	}
	h2 := struct {
		Key, Note, OldHash, NewHash string
	}{raw["key"].(string), raw["note"].(string), raw["old_hash"].(string), raw["new_hash"].(string)}
	if h2.Key != "hot" || h2.Note != "새 지갑 모듈 적용 승인" || h2.OldHash != oldSum || h2.NewHash != newSum {
		t.Errorf("history = %+v (want old %s new %s)", h2, oldSum, newSum)
	}
	if raw["os_user"].(string) == "" {
		t.Error("os_user is empty")
	}

	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("check after accept = %d\n%s\n%s", code, out, errs)
	}

	// A second accept appends; the first line stays.
	chain.setCode("0x")
	if code, _, errs := w.run("accept", "hot", "--note", "되돌림"); code != 0 {
		t.Fatalf("second accept = %d %s", code, errs)
	}
	got := strings.Split(strings.TrimRight(readFile(t, w.history), "\n"), "\n")
	if len(got) != 2 || got[0] != lines[0] {
		t.Errorf("history = %q", got)
	}
}

func TestWatchAcceptRefusesAnUnobservableTarget(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	before := readFile(t, w.base)
	chain.srv.Close()
	code, _, errs := w.run("accept", "hot", "--note", "x")
	if code != 2 || errs == "" {
		t.Fatalf("code=%d %s", code, errs)
	}
	if readFile(t, w.base) != before || fileExists(w.history) {
		t.Fatal("a refused accept changed something")
	}
}

func TestWatchAcceptNewAndRemovedTargets(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	w.writeCfg(
		wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"},
		wTarget{key: "extra", addr: testWallet2, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	if code, _, errs := w.run("accept", "extra", "--note", "새 지갑 추가"); code != 0 {
		t.Fatalf("add: code=%d %s", code, errs)
	}
	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("check after add = %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(readFile(t, w.base), `"extra"`) {
		t.Error("extra not in the baseline")
	}

	w.writeCfg(wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	if code, _, errs := w.run("accept", "extra", "--note", "지갑 제거"); code != 0 {
		t.Fatalf("remove: code=%d %s", code, errs)
	}
	if strings.Contains(readFile(t, w.base), `"extra"`) {
		t.Error("extra is still in the baseline")
	}
	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("check after remove = %d\n%s\n%s", code, out, errs)
	}
	if n := strings.Count(strings.TrimSpace(readFile(t, w.history)), "\n") + 1; n != 2 {
		t.Errorf("history lines = %d", n)
	}
}

func TestWatchSingleRPCNote(t *testing.T) {
	c := newFakeChain(t)
	t.Setenv("ADK_T_ONE", c.srv.URL)
	w := newWsp(t, wTarget{key: "solo", addr: testWallet, envs: "ADK_T_ONE"})
	mustInit(t, w)
	code, out, errs := w.run("check")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	for name, s := range map[string]string{"stdout": out, "stderr": errs} {
		if !strings.Contains(s, "solo") || !strings.Contains(s, "교차 확인") {
			t.Errorf("%s lacks the single-RPC note: %q", name, s)
		}
	}
	// Two different endpoints: no note.
	t.Setenv("ADK_T_TWO", c.srv.URL+"/other")
	w2 := newWsp(t, wTarget{key: "pair", addr: testWallet, envs: "ADK_T_ONE,ADK_T_TWO"})
	mustInit(t, w2)
	if _, out, _ := w2.run("check"); strings.Contains(out, "교차 확인") {
		t.Errorf("unexpected note: %s", out)
	}
}

func TestWatchRedactsURLs(t *testing.T) {
	const apiKey = "ZXQ9-secret" + "-API-key-7f3a"
	down, bad, ok := newFakeChain(t), newFakeChain(t), newFakeChain(t)
	hookBodies := make(chan string, 8)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hookBodies <- string(b)
	}))
	t.Cleanup(hookSrv.Close)

	urls := map[string]string{
		"ADK_T_DOWN": down.srv.URL + "/v2/" + apiKey + "?apikey=" + apiKey,
		"ADK_T_BAD":  bad.srv.URL + "/v2/" + apiKey,
		"ADK_T_OK":   ok.srv.URL + "/v2/" + apiKey,
	}
	hookURL := hookSrv.URL + "/hooks/" + apiKey
	for k, v := range urls {
		t.Setenv(k, v)
	}
	t.Setenv("ADK_WATCH_WEBHOOK", hookURL)
	w := newWsp(t,
		wTarget{key: "down", addr: testWallet, envs: "ADK_T_DOWN"},
		wTarget{key: "bad", addr: testWallet2, envs: "ADK_T_BAD"},
		wTarget{key: "ok", addr: "0x3333333333333333333333333333333333333333", envs: "ADK_T_OK"})
	var all strings.Builder
	record := func(label string, code int, out, errs string) {
		fmt.Fprintf(&all, "--- %s (%d)\n%s\n%s\n", label, code, out, errs)
	}
	{
		code, out, errs := w.run("init")
		record("init", code, out, errs)
		if code != 0 {
			t.Fatalf("init: %s", errs)
		}
	}

	// An address pasted where a variable name belongs must not be echoed either.
	w.writeCfg(
		wTarget{key: "down", addr: testWallet, envs: "ADK_T_DOWN"},
		wTarget{key: "bad", addr: testWallet2, envs: "ADK_T_BAD"},
		wTarget{key: "ok", addr: "0x3333333333333333333333333333333333333333", envs: "ADK_T_OK"},
		wTarget{key: "pasted", addr: "0x4444444444444444444444444444444444444444", envs: "https://node.example/v2/" + apiKey})

	downHost := strings.TrimPrefix(down.srv.URL, "http://")
	down.srv.Close()   // connection failure
	bad.setStatus(500) // HTTP failure
	ok.setCode(delegationCode(testDelA))

	outDir := filepath.Join(w.dir, "out")
	code, out, errs := w.run("check", "--format", "md,json", "--out", outDir)
	record("check", code, out, errs)
	if code != 1 {
		t.Fatalf("check = %d\n%s\n%s", code, out, errs)
	}
	ents, _ := os.ReadDir(outDir)
	for _, e := range ents {
		all.WriteString("--- file " + e.Name() + "\n" + readFile(t, filepath.Join(outDir, e.Name())) + "\n")
	}
	select {
	case b := <-hookBodies:
		all.WriteString("--- webhook body\n" + b + "\n")
		if !strings.Contains(b, "WA-001") || !strings.Contains(b, `"down"`) || !strings.Contains(b, `"bad"`) {
			t.Errorf("webhook body = %s", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook was sent")
	}

	// A broken webhook: its warning must not show the address either.
	hookSrv.Close()
	code, out, errs = w.run("check", "--format", "md,json", "--out", outDir)
	record("check with broken webhook", code, out, errs)
	if code != 1 || !strings.Contains(errs, "웹훅") {
		t.Errorf("code=%d stderr=%s", code, errs)
	}

	text := all.String()
	secrets := []string{apiKey, hookURL, hookSrv.URL, down.srv.URL, bad.srv.URL, ok.srv.URL, downHost,
		strings.TrimPrefix(bad.srv.URL, "http://"), strings.TrimPrefix(ok.srv.URL, "http://"), "/v2/", "/hooks/", "node.example"}
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Errorf("output contains %q", s)
		}
	}
	// The failure reasons are still shown, without the address.
	for _, s := range []string{"연결하지 못했습니다", "HTTP 상태 500", "확인 못 함", "환경 변수 이름"} {
		if !strings.Contains(text, s) {
			t.Errorf("output lacks %q", s)
		}
	}
}

func TestScrubRemovesURLParts(t *testing.T) {
	raw := "http://user:pw-123456@node.example.test:8545/v2/KEY-abcdef?token=TOK-xyz789"
	s := newScrubber(raw)
	in := "실패: " + raw + " 그리고 node.example.test:8545 와 /v2/KEY-abcdef 와 TOK-xyz789 와 pw-123456"
	got := s.clean(in)
	for _, bad := range []string{raw, "node.example.test", "KEY-abcdef", "TOK-xyz789", "pw-123456"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q still in %q", bad, got)
		}
	}
	if !strings.Contains(got, "실패") {
		t.Errorf("got %q", got)
	}
}

type hookRec struct {
	mu     sync.Mutex
	bodies []string
}

func (h *hookRec) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.bodies...)
}

func newHook(t *testing.T, status int) (*hookRec, string) {
	t.Helper()
	h := &hookRec{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, string(b))
		h.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
		}
	}))
	t.Cleanup(srv.Close)
	return h, srv.URL
}

func TestWebhookBody(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)

	if code, _, _ := w.run("check"); code != 0 || len(h.all()) != 0 {
		t.Fatalf("a clean check must send nothing: code=%d bodies=%v", code, h.all())
	}
	chain.setCode(delegationCode(testDelA))
	if code, _, errs := w.run("check"); code != 1 {
		t.Fatalf("code=%d %s", code, errs)
	}
	bodies := h.all()
	if len(bodies) != 1 {
		t.Fatalf("bodies = %v", bodies)
	}
	var p struct {
		Findings   []struct{ Key, ID, Severity string }
		Unverified []string
	}
	if err := json.Unmarshal([]byte(bodies[0]), &p); err != nil {
		t.Fatalf("%v: %s", err, bodies[0])
	}
	if len(p.Findings) != 1 || p.Findings[0].Key != "hot" || p.Findings[0].ID != "WA-001" || p.Findings[0].Severity != "critical" || p.Unverified == nil {
		t.Errorf("payload = %s", bodies[0])
	}

	// An unverified target is sent too.
	chain.srv.Close()
	if code, _, _ := w.run("check"); code != 2 {
		t.Fatalf("code=%d", code)
	}
	bodies = h.all()
	if len(bodies) != 2 || !strings.Contains(bodies[1], `"unverified":["hot"]`) {
		t.Errorf("bodies = %v", bodies)
	}
}

func TestWebhookOffByDefault(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	t.Setenv("ADK_WATCH_WEBHOOK", "")
	code, _, errs := w.run("check")
	if code != 1 || strings.Contains(errs, "웹훅") {
		t.Errorf("code=%d stderr=%s", code, errs)
	}
}

func TestWebhookFailureVisible(t *testing.T) {
	redirected, redirectedURL := newHook(t, 0)
	redirect := httptest.NewServer(http.RedirectHandler(redirectedURL+"/landing", http.StatusFound))
	t.Cleanup(redirect.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	_, serverError := newHook(t, 500)

	for name, url := range map[string]string{"server error": serverError, "redirect": redirect.URL, "connection refused": closedURL, "bad address": "::not a url"} {
		t.Run(name, func(t *testing.T) {
			w, chain := oneWallet(t)
			mustInit(t, w)
			chain.setCode(delegationCode(testDelA))
			t.Setenv("ADK_WATCH_WEBHOOK", url)
			code, _, errs := w.run("check")
			if code != 1 {
				t.Errorf("exit code = %d, want 1 (a webhook failure must not change it)", code)
			}
			if !strings.Contains(errs, "웹훅") || strings.Contains(errs, url) {
				t.Errorf("stderr = %q", errs)
			}
		})
	}
	if n := len(redirected.all()); n != 0 {
		t.Errorf("the redirect was followed (%d requests)", n)
	}

	// The same failure on an unverified-only run keeps exit code 2.
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.srv.Close()
	t.Setenv("ADK_WATCH_WEBHOOK", serverError)
	if code, _, errs := w.run("check"); code != 2 || !strings.Contains(errs, "웹훅") {
		t.Errorf("code=%d stderr=%s", code, errs)
	}
}

// fakeTicks makes --every run n rounds without waiting: before round i+1
// starts, step(i) may change the chain; after the last round the context is cancelled.
func fakeTicks(t *testing.T, cancel context.CancelFunc, n int, step func(i int)) {
	t.Helper()
	oldAfter, oldNow := watchAfter, watchNow
	t.Cleanup(func() { watchAfter, watchNow = oldAfter, oldNow })
	i := 0
	now := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	watchNow = func() time.Time { return now }
	watchAfter = func(d time.Duration) <-chan time.Time {
		i++
		if d != time.Minute {
			t.Errorf("interval = %v", d)
		}
		if i >= n {
			cancel()
		} else {
			step(i)
		}
		ch := make(chan time.Time, 1)
		ch <- now
		return ch
	}
}

func decodeReports(t *testing.T, out string) []struct {
	Findings []struct{ ID string }
	Checks   []struct{ Name, Status string }
} {
	t.Helper()
	var reps []struct {
		Findings []struct{ ID string }
		Checks   []struct{ Name, Status string }
	}
	dec := json.NewDecoder(strings.NewReader(out))
	for dec.More() {
		var r struct {
			Findings []struct{ ID string }
			Checks   []struct{ Name, Status string }
		}
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode: %v\n%s", err, out)
		}
		reps = append(reps, r)
	}
	return reps
}

func TestWatchEvery(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)

	// Rounds: clean, delegation, delegation (same), clean, delegation.
	states := []string{"0x", delegationCode(testDelA), delegationCode(testDelA), "0x", delegationCode(testDelA)}
	chain.setCode(states[0])
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeTicks(t, cancel, len(states), func(i int) { chain.setCode(states[i]) })

	code, out, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
	if code != 1 {
		t.Fatalf("exit code = %d, want the worst seen (1)\n%s", code, errs)
	}
	reps := decodeReports(t, out)
	if len(reps) != 4 {
		t.Fatalf("%d reports, want 4 (the repeated state is not reported again)\n%s", len(reps), out)
	}
	wantFindings := []int{0, 1, 0, 1}
	for i, r := range reps {
		if len(r.Findings) != wantFindings[i] {
			t.Errorf("report %d has %d findings", i, len(r.Findings))
		}
	}
	if n := len(h.all()); n != 3 {
		t.Errorf("%d webhooks, want 3: delegation, back to clean, delegation", n)
	}
}

func TestWatchEveryWorstCode(t *testing.T) {
	cases := []struct {
		name   string
		states []string // "down" closes the chain
		want   int
	}{
		{"clean only", []string{"0x", "0x"}, 0},
		{"unverified then clean", []string{"down", "0x"}, 2},
		{"finding beats unverified", []string{"down", delegationCode(testDelA), "down"}, 1},
		{"finding then clean stays 1", []string{delegationCode(testDelA), "0x"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, chain := oneWallet(t)
			mustInit(t, w)
			var mu sync.Mutex
			apply := func(s string) {
				mu.Lock()
				defer mu.Unlock()
				if s == "down" {
					chain.setStatus(503)
					return
				}
				chain.setStatus(0)
				chain.setCode(s)
			}
			apply(c.states[0])
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fakeTicks(t, cancel, len(c.states), func(i int) { apply(c.states[i]) })
			code, out, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
			if code != c.want {
				t.Errorf("exit code = %d, want %d\n%s\n%s", code, c.want, out, errs)
			}
		})
	}
}

func TestWatchEveryRejectsBadIntervals(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	for _, v := range []string{"0", "0s", "-5s", "abc"} {
		if code, _, errs := w.run("check", "--every", v); code != 2 || !strings.Contains(errs, "--every") {
			t.Errorf("--every %s: code=%d %s", v, code, errs)
		}
	}
	for _, sub := range []string{"init", "accept"} {
		if code, _, errs := w.run(sub, "--every", "1m", "hot", "--note", "x"); code != 2 || !strings.Contains(errs, "--every") {
			t.Errorf("%s --every: code=%d %s", sub, code, errs)
		}
	}
}

func TestWatchEveryWithoutBaselineStopsAtOnce(t *testing.T) {
	w, _ := oneWallet(t)
	fakeTicks(t, func() { t.Error("loop started") }, 1000, func(int) {})
	if code, _, _ := w.run("check", "--every", "1m"); code != 2 {
		t.Errorf("code=%d", code)
	}
}

func TestWatchUsageAndFlags(t *testing.T) {
	var o, e bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, &o, &e); code != 0 || !strings.Contains(o.String(), "adk watch") {
		t.Errorf("usage lacks watch: %s", o.String())
	}
	w, _ := oneWallet(t)
	for name, args := range map[string][]string{
		"no subcommand":   {"watch"},
		"unknown":         {"watch", "frobnicate"},
		"bad fail-on":     {"watch", "check", "--fail-on", "info", "--config", w.cfg, "--baseline", w.base},
		"sarif":           {"watch", "check", "--format", "sarif", "--config", w.cfg, "--baseline", w.base},
		"two formats/out": {"watch", "check", "--format", "md,json", "--config", w.cfg, "--baseline", w.base},
	} {
		o.Reset()
		e.Reset()
		if code := Run(context.Background(), args, &o, &e); code != 2 || e.Len() == 0 {
			t.Errorf("%s: code=%d stderr=%q", name, code, e.String())
		}
	}
}

func TestWatchFailOn(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	if code, _, _ := w.run("check", "--fail-on", "critical"); code != 1 {
		t.Errorf("critical finding at critical: %d", code)
	}
	chain.setCode("0x6001")
	if code, out, _ := w.run("check", "--fail-on", "critical"); code != 0 || !strings.Contains(out, "WA-003") {
		t.Errorf("high finding at critical: %d\n%s", code, out)
	}
	if code, _, _ := w.run("check"); code != 1 {
		t.Errorf("high finding at the default: %d", code)
	}
}

func TestWatchCancelled(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, out, errs := w.runCtx(ctx, "check")
	if code != 2 || out != "" || !strings.Contains(errs, msgCancelled) {
		t.Errorf("code=%d stdout=%q stderr=%q", code, out, errs)
	}
}

// Drill D2, against an in-process fake chain: the delegation of an account is
// created and then removed. This is not a run against a real local chain.
func TestDrillD2FakeChain(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)

	firstCode, first, _ := w.run("check", "--format", "json")
	if firstCode != 0 {
		t.Fatalf("step 1: code=%d\n%s", firstCode, first)
	}

	chain.setCode(delegationCode(testDelA)) // 0x -> 0xef0100 + address
	code, out, _ := w.run("check", "--format", "json")
	if code != 1 || !strings.Contains(out, "WA-001") || !strings.Contains(out, "critical") {
		t.Fatalf("step 2: code=%d\n%s", code, out)
	}

	chain.setCode("0x") // delegation removed
	lastCode, last, _ := w.run("check", "--format", "json")
	if lastCode != 0 {
		t.Fatalf("step 3: code=%d\n%s", lastCode, last)
	}
	// Same output state as step 1: only the time of the check differs.
	if a, b := withoutTime(t, first), withoutTime(t, last); a != b {
		t.Errorf("step 3 differs from step 1:\n%s\n%s", a, b)
	}
}

func withoutTime(t *testing.T, js string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "scanned_at")
	b, _ := json.Marshal(m)
	return string(b)
}

func TestWatchTextsAreInPlace(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	_, out, _ := w.run("check", "--format", "json")
	var rep struct {
		Findings []struct {
			ID        string
			ExplainKo string `json:"explain_ko"`
			Fix       string
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Findings) != 1 {
		t.Fatalf("%v\n%s", err, out)
	}
	f := rep.Findings[0]
	if f.ExplainKo == "" || f.Fix == "" {
		t.Errorf("finding = %+v", f)
	}
}

// Cancelling before any round has finished verified nothing: it is exit 2,
// like a cancelled one-shot check, not 0.
func TestWatchEveryCancelledInFirstRound(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chain.setHook(cancel)
	code, out, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
}

func TestWatchRejectsAddressAsEnvName(t *testing.T) {
	const key = "SECRETKEY123"
	c := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", c.srv.URL)
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A"})
	mustInit(t, w)
	w.writeCfg(wTarget{key: "hot", addr: testWallet, envs: "https://node.example/v2/" + key})
	for _, args := range [][]string{{"init", "--baseline", filepath.Join(w.dir, "other.json")}, {"check"}, {"check", "--format", "json"}, {"accept", "hot", "--note", "x"}} {
		code, out, errs := w.run(args[0], args[1:]...)
		all := out + errs
		if code != 2 || strings.Contains(all, key) || strings.Contains(all, "node.example") || !strings.Contains(all, "hot") || !strings.Contains(all, "환경 변수 이름") {
			t.Errorf("%v: code=%d\n%s", args, code, all)
		}
	}
}

// A baseline that goes bad during --every is a state change: it is reported
// and sent to the webhook once, and again only after it recovers and breaks.
func TestWatchEveryBaselineGoesBad(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	good := readFile(t, w.base)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)
	put := func(s string) {
		if err := os.WriteFile(w.base, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Rounds: good, bad, bad (same), good, bad.
	states := []string{good, "{broken", "{broken", good, "{broken"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeTicks(t, cancel, len(states), func(i int) { put(states[i]) })
	code, out, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\n%s", code, errs)
	}
	if n := len(decodeReports(t, out)); n != 4 {
		t.Errorf("%d reports, want 4\n%s", n, out)
	}
	bodies := h.all()
	if len(bodies) != 3 || !strings.Contains(bodies[0], `"baseline_error":true`) || strings.Contains(bodies[1], `"baseline_error":true`) {
		t.Errorf("webhooks = %v, want bad, recovered, bad", bodies)
	}
	if strings.Contains(strings.Join(bodies, ""), url) {
		t.Error("webhook body holds the address")
	}
}
