package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

const (
	selOwners    = "0xa0e67e2b"
	selThreshold = "0xe75235b8"
	slotImpl     = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
	slotAdminW   = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)

func addrWordT(a string) string {
	return strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(a, "0x"))
}

func ownersRet(addrs ...string) string {
	s := "0x" + strings.Repeat("0", 62) + "20" + strings.Repeat("0", 63) + string(rune('0'+len(addrs)))
	for _, a := range addrs {
		s += addrWordT(a)
	}
	return s
}

// safeChain sets up one Safe, read through two addresses of one fake chain.
func safeChain(t *testing.T) (*wsp, *fakeChain) {
	t.Helper()
	c := newFakeChain(t)
	c.code = "0x6080"
	c.calls = map[string]string{selOwners: ownersRet(testDelA, testDelB), selThreshold: "0x" + strings.Repeat("0", 63) + "2"}
	c.slots = map[string]string{"0x0": "0x" + addrWordT(testDelA)}
	t.Setenv("ADK_T_RPC_A", c.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", c.srv.URL+"/b")
	return newWsp(t, wTarget{key: "vault", addr: testWallet, typ: "safe", envs: "ADK_T_RPC_A,ADK_T_RPC_B"}), c
}

type jsonReport struct {
	Findings []struct {
		ID, Location, Evidence string
		Severity               any
	}
	Checks []struct {
		Name, Status, Error string
		Warnings, Notes     []string
	}
}

func parseReport(t *testing.T, out string) jsonReport {
	t.Helper()
	var r jsonReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	return r
}

func (r jsonReport) check(name string) (status, errText string, notes []string) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status, c.Error, c.Notes
		}
	}
	return "", "", nil
}

func (r jsonReport) ids() []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.ID)
	}
	return out
}

// C1: pointing the config at another account must not read as no change.
func TestWatchEditedAddressIsWA007(t *testing.T) {
	w, _ := oneWallet(t)
	out := mustInit(t, w)
	pin := sha64.FindString(out)
	w.writeCfg(wTarget{key: "hot", addr: testWallet2, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})

	code, js, errs := w.run("check", "--format", "json", "--baseline-sha256", pin)
	if code != 1 || !strings.Contains(js, "WA-007") {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	if code, out, errs := w.run("accept", "hot", "--note", "주소를 새 지갑으로 옮김"); code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("check after accept = %d\n%s\n%s", code, out, errs)
	}
}

func TestWatchEditedTypeIsWA007(t *testing.T) {
	w, c := oneWallet(t)
	c.setCode("0x6080")
	mustInit(t, w)
	w.writeCfg(wTarget{key: "hot", addr: testWallet, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	code, js, errs := w.run("check", "--format", "json")
	if code != 1 || !strings.Contains(js, "WA-007") {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
}

// C2: a Safe's logic replaced, so getOwners reverts. It must be a critical
// finding and unverified, not an RPC problem.
func TestWatchSafeLogicTakeover(t *testing.T) {
	w, c := safeChain(t)
	mustInit(t, w)
	before := readFile(t, w.base)

	c.mu.Lock()
	c.slots["0x0"] = "0x" + addrWordT(testDelB)
	c.calls = map[string]string{}
	c.mu.Unlock()

	code, js, errs := w.run("check", "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	r := parseReport(t, js)
	if ids := r.ids(); len(ids) != 1 || ids[0] != "WA-002" {
		t.Fatalf("findings = %v, want only WA-002 for master_copy (unread fields must not read as removed)\n%s", ids, js)
	}
	if !strings.Contains(r.Findings[0].Evidence, "master_copy") {
		t.Errorf("evidence = %q", r.Findings[0].Evidence)
	}
	if st, e, _ := r.check("watch/vault"); st != "failed" || !strings.Contains(e, "확인 못 함") {
		t.Errorf("check = %s %q", st, e)
	}

	// Partial observations are never adopted.
	if code, out, errs := w.run("accept", "vault", "--note", "x"); code != 2 {
		t.Errorf("accept = %d\n%s\n%s", code, out, errs)
	}
	if readFile(t, w.base) != before || fileExists(w.history) {
		t.Error("a refused accept changed something")
	}
}

func TestWatchInitRefusesAPartialObservation(t *testing.T) {
	w, c := safeChain(t)
	c.mu.Lock()
	c.calls = map[string]string{selOwners: ownersRet(testDelA)}
	c.mu.Unlock()
	code, out, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "vault") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if fileExists(w.base) {
		t.Error("a baseline was written")
	}
}

// I1: a wrong address or type must not be accepted and then read clean forever.
func TestWatchInitRefusesAnImplausibleTarget(t *testing.T) {
	two := "0x" + strings.Repeat("0", 63) + "2"
	zeroOwners := "0x" + strings.Repeat("0", 62) + "20" + strings.Repeat("0", 64)
	cases := []struct {
		name, typ, code string
		calls, slots    map[string]string
	}{
		{"contract without code", "contract", "0x", nil, nil},
		{"proxy without code", "proxy", "0x", nil, map[string]string{slotImpl: "0x" + addrWordT(testDelA)}},
		{"proxy with an empty implementation slot", "proxy", "0x6080", nil, nil},
		{"safe without code", "safe", "0x", map[string]string{selOwners: ownersRet(testDelA), selThreshold: two}, nil},
		{"safe with no owners", "safe", "0x6080", map[string]string{selOwners: zeroOwners, selThreshold: two}, nil},
		{"safe with threshold 0", "safe", "0x6080", map[string]string{selOwners: ownersRet(testDelA), selThreshold: "0x" + strings.Repeat("0", 64)}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chain := newFakeChain(t)
			chain.code, chain.calls, chain.slots = c.code, c.calls, c.slots
			t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
			t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
			w := newWsp(t, wTarget{key: "thing", addr: testWallet, typ: c.typ, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
			code, out, errs := w.run("init")
			if code != 2 || !strings.Contains(errs, "thing") || !strings.Contains(errs, "type") {
				t.Errorf("code=%d\n%s\n%s", code, out, errs)
			}
			if fileExists(w.base) {
				t.Error("a baseline was written")
			}
		})
	}
}

// A UUPS proxy has no admin in the slot: that is not refused.
func TestWatchInitAcceptsAProxyWithoutAdmin(t *testing.T) {
	chain := newFakeChain(t)
	chain.code, chain.slots = "0x6080", map[string]string{slotImpl: "0x" + addrWordT(testDelA)}
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "uups", addr: testWallet, typ: "proxy", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
}

func TestWatchFirstAcceptRefusesAnImplausibleTarget(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	before := readFile(t, w.base)
	w.writeCfg(
		wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"},
		wTarget{key: "c", addr: testWallet2, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	code, out, errs := w.run("accept", "c", "--note", "새 컨트랙트")
	if code != 2 || !strings.Contains(errs, "c") || !strings.Contains(errs, "type") {
		t.Errorf("code=%d\n%s\n%s", code, out, errs)
	}
	if readFile(t, w.base) != before || fileExists(w.history) {
		t.Error("a refused accept changed something")
	}
}

// Code lost after the baseline is a change, not unverified, and can be accepted.
func TestWatchContractLosingItsCodeIsAChange(t *testing.T) {
	chain := newFakeChain(t)
	chain.code = "0x6080"
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "c", addr: testWallet, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	chain.setCode("0x")
	code, js, errs := w.run("check", "--format", "json")
	if code != 1 || !strings.Contains(js, "WA-003") {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	if st, _, _ := parseReport(t, js).check("watch/c"); st != "ok" {
		t.Errorf("status = %s", st)
	}
	if code, _, errs := w.run("accept", "c", "--note", "폐기 확인"); code != 0 {
		t.Errorf("accept of a known target: code=%d %s", code, errs)
	}
}

// I2: a state is sent until it is delivered.
func TestWatchEveryRetriesAFailedWebhook(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			rw.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ADK_WATCH_WEBHOOK", srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeTicks(t, cancel, 4, func(int) {})
	code, out, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s", code, errs)
	}
	if attempts != 2 {
		t.Errorf("%d attempts, want 2: one failed, one delivered, then quiet", attempts)
	}
	if n := len(decodeReports(t, out)); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
}

func TestWatchEveryRetriesAFailedReport(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	outDir := filepath.Join(w.dir, "out")
	if err := os.WriteFile(outDir, []byte("a file where the folder goes"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeTicks(t, cancel, 3, func(i int) {
		if i == 1 {
			if err := os.Remove(outDir); err != nil {
				t.Error(err)
			}
		}
	})
	code, _, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json", "--out", outDir)
	if code != 1 {
		t.Fatalf("code=%d\n%s", code, errs)
	}
	if !fileExists(filepath.Join(outDir, "adk-report.json")) {
		t.Errorf("the report was not written once the path was free\n%s", errs)
	}
}

// Minor: a report write failure must not hide a critical finding: 1 beats 2.
func TestWatchReportWriteFailureKeepsExitOne(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	outDir := filepath.Join(w.dir, "out")
	if err := os.WriteFile(outDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w.run("check", "--format", "json", "--out", outDir); code != 2 {
		t.Errorf("clean state: code=%d %s", code, errs)
	}
	chain.setCode(delegationCode(testDelA))
	if code, _, errs := w.run("check", "--format", "json", "--out", outDir); code != 1 {
		t.Errorf("critical state: code=%d %s", code, errs)
	}
}

// I3: both default clients ignore an environment proxy.
func TestWebhookClientIgnoresEnvProxyByDefault(t *testing.T) {
	tr, ok := webhookClient(false).Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Errorf("default webhook transport = %#v", webhookClient(false).Transport)
	}
	tr, ok = webhookClient(true).Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Errorf("--allow-env-proxy must use the proxy: %#v", webhookClient(true).Transport)
	}
}

// Run in a child process, because net/http reads the proxy variables once.
func TestWatchChildProcess(t *testing.T) {
	raw := os.Getenv("ADK_T_CHILD_ARGS")
	if raw == "" {
		t.Skip("helper for TestWatchAllowEnvProxyGoesThroughTheProxy")
	}
	code := Run(context.Background(), strings.Split(raw, "\x1f"), os.Stdout, os.Stderr)
	fmt.Printf("\nchild-exit=%d\n", code)
}

// --allow-env-proxy reaches the RPC and webhook clients. rpc.invalid and
// hook.invalid are never resolved: every request goes to the local proxy.
func TestWatchAllowEnvProxyGoesThroughTheProxy(t *testing.T) {
	chain := newFakeChain(t)
	var mu sync.Mutex
	hosts := map[string]int{}
	proxy := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts[r.URL.Host]++
		mu.Unlock()
		chain.srv.Config.Handler.ServeHTTP(rw, r)
	}))
	t.Cleanup(proxy.Close)

	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A"})
	child := func(sub string) string {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestWatchChildProcess$", "-test.v")
		args := []string{"watch", sub, "--allow-env-proxy", "--config", w.cfg, "--baseline", w.base}
		cmd.Env = append(os.Environ(),
			"ADK_T_CHILD_ARGS="+strings.Join(args, "\x1f"),
			"ADK_T_RPC_A=http://rpc.invalid/v2/KEY", "ADK_WATCH_WEBHOOK=http://hook.invalid/h",
			"HTTP_PROXY="+proxy.URL, "http_proxy="+proxy.URL, "NO_PROXY=", "no_proxy=")
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if out := child("init"); !strings.Contains(out, "child-exit=0") {
		t.Fatalf("init through the proxy:\n%s", out)
	}
	chain.setCode(delegationCode(testDelA))
	if out := child("check"); !strings.Contains(out, "child-exit=1") {
		t.Fatalf("check through the proxy:\n%s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if hosts["rpc.invalid"] == 0 || hosts["hook.invalid"] == 0 {
		t.Errorf("hosts seen by the proxy = %v", hosts)
	}
}

// I4: removing a delegation is WA-006, medium, and is sent.
func TestWatchDelegateRemovalIsWA006(t *testing.T) {
	w, chain := oneWallet(t)
	chain.setCode(delegationCode(testDelA))
	mustInit(t, w)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)
	chain.setCode("0x")
	code, js, errs := w.run("check", "--format", "json")
	if code != 0 || !strings.Contains(js, "WA-006") || strings.Contains(js, `"id": "WA-005"`) {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	if bodies := h.all(); len(bodies) != 1 || !strings.Contains(bodies[0], "WA-006") || !strings.Contains(bodies[0], "medium") {
		t.Errorf("webhooks = %v", bodies)
	}
	if code, _, _ := w.run("check", "--fail-on", "medium"); code != 1 {
		t.Errorf("--fail-on medium: code=%d", code)
	}
}

// Add then remove under --every: the return to clean is sent, and both
// states stay on disk after the report is overwritten.
func TestWatchEveryLogsAndSendsEveryStateChange(t *testing.T) {
	const apiKey = "ZXQ9-secret" + "-API-key-7f3a"
	chain := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/v2/"+apiKey)
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b/"+apiKey)
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url+"/hooks/"+apiKey)

	states := []string{"0x", delegationCode(testDelA), delegationCode(testDelA), "0x"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeTicks(t, cancel, len(states), func(i int) { chain.setCode(states[i]) })
	outDir := filepath.Join(w.dir, "out")
	code, _, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json", "--out", outDir)
	if code != 1 {
		t.Fatalf("code=%d\n%s", code, errs)
	}
	if strings.Contains(readFile(t, filepath.Join(outDir, "adk-report.json")), "WA-001") {
		t.Error("the last report should show the clean state")
	}

	bodies := h.all()
	if len(bodies) != 2 || !strings.Contains(bodies[0], "WA-001") || !strings.Contains(bodies[1], `"findings":[]`) {
		t.Errorf("webhooks = %v", bodies)
	}

	raw := readFile(t, filepath.Join(w.dir, "adk-watch-events.jsonl"))
	if strings.Contains(raw, apiKey) || strings.Contains(raw, "127.0.0.1") {
		t.Errorf("events hold an address: %s", raw)
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) != 3 {
		t.Fatalf("events = %q, want clean, WA-001, clean", lines)
	}
	want := []struct {
		code int
		id   string
		key  string
	}{{0, "", ""}, {1, "WA-001", "hot"}, {0, "", ""}}
	for i, l := range lines {
		var e struct {
			Time       string   `json:"time"`
			Code       int      `json:"code"`
			FindingIDs []string `json:"finding_ids"`
			TargetKeys []string `json:"target_keys"`
		}
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		if e.Time == "" || e.Code != want[i].code {
			t.Errorf("line %d = %s", i, l)
		}
		if want[i].id != "" && (len(e.FindingIDs) != 1 || e.FindingIDs[0] != want[i].id || len(e.TargetKeys) != 1 || e.TargetKeys[0] != want[i].key) {
			t.Errorf("line %d = %s", i, l)
		}
		if want[i].id == "" && (e.FindingIDs == nil || len(e.FindingIDs) != 0 || len(e.TargetKeys) != 0) {
			t.Errorf("line %d = %s", i, l)
		}
	}
}

func TestWatchOneShotCheckWritesNoEvents(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	w.run("check")
	if fileExists(filepath.Join(w.dir, "adk-watch-events.jsonl")) {
		t.Error("the events file is for --every")
	}
}

func TestWatchEveryEventsNameUnverifiedTargets(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setStatus(503)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fakeTicks(t, cancel, 1, func(int) {})
	if code, _, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json"); code != 2 {
		t.Fatalf("code=%d %s", code, errs)
	}
	raw := readFile(t, filepath.Join(w.dir, "adk-watch-events.jsonl"))
	if !strings.Contains(raw, `"target_keys":["hot"]`) || !strings.Contains(raw, `"code":2`) {
		t.Errorf("events = %s", raw)
	}
}

// Small item: the same unverified target with another reason is the same state.
func TestWatchEveryUnverifiedReasonIsNotAStateChange(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)
	chain.setStatus(503)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statuses := []int{503, 500, 502}
	fakeTicks(t, cancel, len(statuses), func(i int) { chain.setStatus(statuses[i]) })
	code, out, errs := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
	if code != 2 {
		t.Fatalf("code=%d %s", code, errs)
	}
	if n := len(decodeReports(t, out)); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
	if n := len(h.all()); n != 1 {
		t.Errorf("%d webhooks, want 1", n)
	}
}

// I5: accept shows what it commits, and --expect refuses another value.
func TestWatchAcceptShowsAndRecordsValues(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelB))
	code, out, errs := w.run("accept", "hot", "--note", "reviewed A")
	if code != 0 {
		t.Fatalf("code=%d %s", code, errs)
	}
	if !strings.Contains(out, "delegate") || !strings.Contains(out, testDelB) {
		t.Errorf("stdout does not show the new value:\n%s", out)
	}
	h := readFile(t, w.history)
	var e struct {
		Changes []struct{ Field, Old, New string } `json:"changes"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(h)), &e); err != nil {
		t.Fatalf("%v: %s", err, h)
	}
	if len(e.Changes) != 1 || e.Changes[0].Field != "delegate" || e.Changes[0].Old != "" || e.Changes[0].New != testDelB {
		t.Errorf("history = %s", h)
	}
}

func TestWatchAcceptExpect(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	before := readFile(t, w.base)
	chain.setCode(delegationCode(testDelB))

	refused := func(args ...string) {
		t.Helper()
		code, out, errs := w.run("accept", append([]string{"hot", "--note", "reviewed"}, args...)...)
		if code != 2 || errs == "" {
			t.Errorf("%v: code=%d\n%s\n%s", args, code, out, errs)
		}
		if readFile(t, w.base) != before || fileExists(w.history) {
			t.Fatalf("%v: a refused accept changed something", args)
		}
	}
	refused("--expect", "delegate="+testDelA)
	refused("--expect", "delegate="+testDelB, "--expect", "address="+testWallet2)
	refused("--expect", "delegate")
	refused("--expect", "no_such_field=")

	if _, _, errs := w.run("accept", "hot", "--note", "reviewed", "--expect", "delegate="+testDelA); !strings.Contains(errs, testDelB) || !strings.Contains(errs, testDelA) {
		t.Errorf("the refusal must show both values: %s", errs)
	}
	code, out, errs := w.run("accept", "hot", "--note", "reviewed", "--expect", "delegate="+strings.ToUpper(testDelB[2:4])+testDelB[4:], "--expect", "type=eoa")
	if code == 0 {
		t.Errorf("a value without its 0x prefix is not the same text: %s", out)
	}
	code, out, errs = w.run("accept", "hot", "--note", "reviewed", "--expect", "delegate=0x"+strings.ToUpper(testDelB[2:]), "--expect", "type=eoa")
	if code != 0 {
		t.Errorf("matching --expect: code=%d\n%s\n%s", code, out, errs)
	}
	// Already the same, but not what was expected: still refused.
	if code, _, _ := w.run("accept", "hot", "--note", "again", "--expect", "delegate="+testDelA); code != 2 {
		t.Errorf("unchanged with a wrong --expect: code=%d", code)
	}
	if code, _, errs := w.run("check", "--expect", "delegate="+testDelA); code != 2 || !strings.Contains(errs, "--expect") {
		t.Errorf("--expect on check: code=%d %s", code, errs)
	}
}

func TestWatchAcceptExpectOnARemovedTargetIsRefused(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	before := readFile(t, w.base)
	w.writeCfg(wTarget{key: "other", addr: testWallet2, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	if code, _, _ := w.run("accept", "hot", "--note", "제거", "--expect", "type=eoa"); code != 2 {
		t.Errorf("code=%d", code)
	}
	if readFile(t, w.base) != before {
		t.Error("the baseline changed")
	}
}

// I6: a delegate outside the allow list in the starting state is pointed out.
func TestWatchDelegateOutsideAllowListIsPointedOut(t *testing.T) {
	chain := newFakeChain(t)
	chain.code = delegationCode(testDelA)
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B", allowed: []string{testDelB}})

	code, _, errs := w.run("init")
	if code != 0 || !strings.Contains(errs, "경고") || !strings.Contains(errs, "allowed_delegates") || !strings.Contains(errs, testDelA) {
		t.Fatalf("init: code=%d stderr=%s", code, errs)
	}
	code, js, _ := w.run("check", "--format", "json")
	r := parseReport(t, js)
	_, _, notes := r.check("watch/hot")
	if code != 0 || len(r.Findings) != 0 || !strings.Contains(strings.Join(notes, " "), "allowed_delegates") {
		t.Errorf("check: code=%d notes=%v\n%s", code, notes, js)
	}

	chain.setCode(delegationCode(testDelB))
	if code, _, errs := w.run("accept", "hot", "--note", "b로 교체"); code != 0 || strings.Contains(errs, "allowed_delegates") {
		t.Errorf("accept inside the list: code=%d %s", code, errs)
	}
	chain.setCode(delegationCode(testDelA))
	if code, _, errs := w.run("accept", "hot", "--note", "a로 교체"); code != 0 || !strings.Contains(errs, "allowed_delegates") {
		t.Errorf("accept outside the list: code=%d %s", code, errs)
	}
}

func TestWatchDelegateInsideAllowListHasNoNote(t *testing.T) {
	chain := newFakeChain(t)
	chain.code = delegationCode(testDelA)
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B", allowed: []string{testDelA}})
	if _, _, errs := w.run("init"); strings.Contains(errs, "allowed_delegates") {
		t.Errorf("init: %s", errs)
	}
	_, js, _ := w.run("check", "--format", "json")
	if _, _, notes := parseReport(t, js).check("watch/hot"); len(notes) != 0 {
		t.Errorf("notes = %v", notes)
	}
}

// I7: a stuck node is not a clean result.
func TestWatchStaleBlock(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.mu.Lock()
	chain.blockAge = 2 * time.Hour
	chain.mu.Unlock()
	code, js, errs := w.run("check", "--format", "json")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	st, e, _ := parseReport(t, js).check("watch/hot")
	if st != "failed" || !strings.Contains(e, "RPC 1") || !strings.Contains(e, "블록") {
		t.Errorf("check = %s %q", st, e)
	}
	// A change seen on that node is still a finding.
	chain.setCode(delegationCode(testDelA))
	if code, js, _ := w.run("check", "--format", "json"); code != 1 || !strings.Contains(js, "WA-001") {
		t.Errorf("code=%d\n%s", code, js)
	}
	// init and accept do not adopt it.
	if code, _, _ := w.run("accept", "hot", "--note", "x"); code != 2 {
		t.Errorf("accept on a stale node: code=%d", code)
	}
}

func TestWatchStaleBlockOnOneOfTwo(t *testing.T) {
	a, b := newFakeChain(t), newFakeChain(t)
	t.Setenv("ADK_T_A", a.srv.URL)
	t.Setenv("ADK_T_B", b.srv.URL)
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_A,ADK_T_B"})
	mustInit(t, w)
	b.mu.Lock()
	b.blockAge = 2 * time.Hour
	b.mu.Unlock()
	code, js, _ := w.run("check", "--format", "json")
	st, e, _ := parseReport(t, js).check("watch/hot")
	if code != 2 || st != "failed" || !strings.Contains(e, "RPC 2") {
		t.Errorf("code=%d %s %q", code, st, e)
	}
}

func TestWatchMaxBlockAgeOption(t *testing.T) {
	for name, extra := range map[string]string{
		"disabled": "      max_block_age: \"0\"\n",
		"longer":   "      max_block_age: \"3h\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			chain := newFakeChain(t)
			chain.blockAge = 2 * time.Hour
			t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
			t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
			w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B", extra: extra})
			mustInit(t, w)
			if code, out, errs := w.run("check"); code != 0 {
				t.Errorf("code=%d\n%s\n%s", code, out, errs)
			}
		})
	}
}

// I9: no cross-check happens when both names hold one address.
func TestWatchSingleRPCNoteComparesAddresses(t *testing.T) {
	chain := newFakeChain(t)
	t.Setenv("ADK_T_A", chain.srv.URL)
	t.Setenv("ADK_T_B", chain.srv.URL)
	for _, envs := range []string{"ADK_T_A,ADK_T_A", "ADK_T_A,ADK_T_B"} {
		w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: envs})
		code, _, errs := w.run("init")
		if code != 0 || !strings.Contains(errs, "교차 확인") {
			t.Errorf("%s: code=%d stderr=%s", envs, code, errs)
		}
	}
}

// I10: an unset shell variable must not turn the pin off.
func TestWatchEmptyPinIsAnError(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	// The file no longer matches any pin it was given.
	if err := os.WriteFile(w.base, []byte(readFile(t, w.base)+" "), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"check", "--baseline-sha256", ""}, {"check", "--baseline-sha256="}, {"check", "--baseline-sha256", "  "}, {"accept", "hot", "--note", "x", "--baseline-sha256", ""}} {
		code, _, errs := w.run(args[0], args[1:]...)
		if code != 2 || !strings.Contains(errs, "--baseline-sha256") {
			t.Errorf("%v: code=%d stderr=%s", args, code, errs)
		}
	}
}

// Minor: `watch: ok` must not appear when nothing was verified.
func TestWatchOverallCheckFailsWhenNothingWasVerified(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setStatus(503)
	code, js, errs := w.run("check", "--format", "json")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	r := parseReport(t, js)
	if st, _, _ := r.check("watch"); st != "failed" {
		t.Errorf("watch = %q\n%s", st, js)
	}
	if st, e, _ := r.check("watch/hot"); st != "failed" || !strings.Contains(e, "확인 못 함") {
		t.Errorf("watch/hot = %s %q", st, e)
	}
	// The Markdown report is still written, and does not say all is well.
	code, md, _ := w.run("check")
	if code != 2 || !strings.Contains(md, "확인 못 함") || strings.Contains(md, "찾은 문제가 없습니다") {
		t.Errorf("code=%d\n%s", code, md)
	}
}

func TestWatchOverallCheckIsOKWhenOneTargetWasVerified(t *testing.T) {
	a, b := newFakeChain(t), newFakeChain(t)
	t.Setenv("ADK_T_A", a.srv.URL)
	t.Setenv("ADK_T_B", b.srv.URL)
	w := newWsp(t,
		wTarget{key: "up", addr: testWallet, envs: "ADK_T_A"},
		wTarget{key: "down", addr: testWallet2, envs: "ADK_T_B"})
	mustInit(t, w)
	b.setStatus(503)
	_, js, _ := w.run("check", "--format", "json")
	if st, _, _ := parseReport(t, js).check("watch"); st != "ok" {
		t.Errorf("watch = %q", st)
	}
}

func TestWatchEveryBadBaselineMarksOverallCheckFailed(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	good := readFile(t, w.base)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	put := func(s string) {
		if err := os.WriteFile(w.base, []byte(s), 0o600); err != nil {
			t.Error(err)
		}
	}
	fakeTicks(t, cancel, 2, func(int) { put("{broken") })
	_, out, _ := w.runCtx(ctx, "check", "--every", "1m", "--format", "json")
	put(good)
	reps := decodeReports(t, out)
	if len(reps) != 2 {
		t.Fatalf("%d reports\n%s", len(reps), out)
	}
	for _, c := range reps[1].Checks {
		if c.Name == "watch" && c.Status != "failed" {
			t.Errorf("watch = %q", c.Status)
		}
	}
}

// Minor: a stray .adkignore in the working folder cannot hide a watch finding.
func TestWatchIgnoresADKIgnore(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	chain.setCode(delegationCode(testDelA))
	_, js, _ := w.run("check", "--format", "json")
	var rep struct {
		Findings []struct{ Fingerprint string }
	}
	if err := json.Unmarshal([]byte(js), &rep); err != nil || len(rep.Findings) != 1 {
		t.Fatalf("%v\n%s", err, js)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".adkignore"), []byte(rep.Findings[0].Fingerprint+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	code, js, _ := w.run("check", "--format", "json")
	if code != 1 || !strings.Contains(js, "WA-001") {
		t.Errorf("code=%d\n%s", code, js)
	}
}

// Small item: a note on a completed target does not use the "could not
// check" banner, and "no problems found" still stands.
func TestWatchNoteDoesNotUseTheFailureBanner(t *testing.T) {
	c := newFakeChain(t)
	t.Setenv("ADK_T_ONE", c.srv.URL)
	w := newWsp(t, wTarget{key: "solo", addr: testWallet, envs: "ADK_T_ONE"})
	mustInit(t, w)
	code, out, errs := w.run("check")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	for name, s := range map[string]string{"stdout": out, "stderr": errs} {
		if strings.Contains(s, "일부 점검을 하지 못했습니다") {
			t.Errorf("%s uses the failure banner:\n%s", name, s)
		}
		if !strings.Contains(s, "solo") || !strings.Contains(s, "교차 확인") {
			t.Errorf("%s lacks the note:\n%s", name, s)
		}
	}
	if !strings.Contains(out, "찾은 문제가 없습니다") {
		t.Errorf("stdout:\n%s", out)
	}
	_, js, _ := w.run("check", "--format", "json")
	if _, _, notes := parseReport(t, js).check("watch/solo"); len(notes) != 1 {
		t.Errorf("notes = %v\n%s", notes, js)
	}
}

// Small item: options are checked for init, check and accept alike.
func TestWatchRejectsUnknownOptions(t *testing.T) {
	w, _ := oneWallet(t)
	mustInit(t, w)
	w.writeCfg(wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B", extra: "      allowed_delegate: [\"" + testDelA + "\"]\n"})
	for _, args := range [][]string{{"init", "--baseline", filepath.Join(w.dir, "other.json")}, {"check"}, {"accept", "hot", "--note", "x"}} {
		code, _, errs := w.run(args[0], args[1:]...)
		if code != 2 || !strings.Contains(errs, "allowed_delegate") || !strings.Contains(errs, "hot") {
			t.Errorf("%v: code=%d stderr=%s", args, code, errs)
		}
	}
}

// Small item: plain http is pointed out, without the address, unless local.
func TestWatchPlainHTTPNote(t *testing.T) {
	const key = "SECRETKEY123"
	t.Setenv("ADK_T_RPC_A", "https://node-a.example/v2/"+key)
	t.Setenv("ADK_T_RPC_B", "http://node-b.example/v2/"+key)
	tg := watch.Target{Key: "hot", Kind: "evm-wallet", Options: map[string]any{"rpc_url_env": "ADK_T_RPC_A,ADK_T_RPC_B"}}
	notes := strings.Join(targetNotes(tg), " ")
	if !strings.Contains(notes, "RPC 2") || !strings.Contains(notes, "http") || strings.Contains(notes, "RPC 1") {
		t.Errorf("notes = %q", notes)
	}
	if strings.Contains(notes, key) || strings.Contains(notes, "node-b") {
		t.Errorf("the note shows the address: %q", notes)
	}
	for _, local := range []string{"http://localhost:8545", "http://127.0.0.1:8545/x", "http://[::1]:8545", "http://anvil.localhost:8545"} {
		t.Setenv("ADK_T_RPC_B", local)
		if notes := strings.Join(targetNotes(tg), " "); strings.Contains(notes, "암호화") {
			t.Errorf("%s: %q", local, notes)
		}
	}
	t.Setenv("ADK_T_RPC_B", "http://localhost.example:8545")
	if notes := strings.Join(targetNotes(tg), " "); !strings.Contains(notes, "암호화") {
		t.Errorf("a name that only starts with localhost is not local: %q", notes)
	}
}
