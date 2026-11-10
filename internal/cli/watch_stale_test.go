package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// N2: accepting WA-007 must run the same plausibility check as init.
func TestWatchAcceptRefusesAnImplausibleEditedTarget(t *testing.T) {
	t.Run("contract moved to an address without code", func(t *testing.T) {
		chain := newFakeChain(t)
		chain.code = "0x6080"
		t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
		t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
		w := newWsp(t, wTarget{key: "token", addr: testWallet, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
		mustInit(t, w)
		before := readFile(t, w.base)

		w.writeCfg(wTarget{key: "token", addr: testWallet2, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
		chain.setCode("0x")
		code, js, _ := w.run("check", "--format", "json")
		if code != 1 || !strings.Contains(js, "WA-007") || !strings.Contains(js, "WA-003") {
			t.Fatalf("check: code=%d\n%s", code, js)
		}
		code, out, errs := w.run("accept", "token", "--note", "주소 변경")
		if code != 2 {
			t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
		}
		if !strings.Contains(errs, "token") || !strings.Contains(errs, "type") || !strings.Contains(errs, "주소") {
			t.Errorf("the message must name the target and say the type or address may be wrong: %s", errs)
		}
		if readFile(t, w.base) != before || fileExists(w.history) {
			t.Error("a refused accept changed the baseline or the history")
		}
		// Still reported: it does not read clean.
		if code, _, _ := w.run("check"); code != 1 {
			t.Errorf("check after the refusal: code=%d", code)
		}
	})

	t.Run("eoa edited to a proxy with an empty implementation slot", func(t *testing.T) {
		chain := newFakeChain(t)
		t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
		t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
		w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
		mustInit(t, w)
		before := readFile(t, w.base)

		w.writeCfg(wTarget{key: "hot", addr: testWallet, typ: "proxy", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
		chain.setCode("0x6080")
		code, out, errs := w.run("accept", "hot", "--note", "종류 변경")
		if code != 2 || !strings.Contains(errs, "hot") || !strings.Contains(errs, "type") {
			t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
		}
		if readFile(t, w.base) != before || fileExists(w.history) {
			t.Error("a refused accept changed the baseline or the history")
		}
	})
}

func TestWatchAcceptAllowsAPlausibleEditedTarget(t *testing.T) {
	chain := newFakeChain(t)
	chain.code = "0x6080"
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "token", addr: testWallet, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	w.writeCfg(wTarget{key: "token", addr: testWallet2, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	if code, out, errs := w.run("accept", "token", "--note", "새 주소로 옮김"); code != 0 {
		t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
	}
	if code, _, _ := w.run("check"); code != 0 {
		t.Errorf("check: code=%d", code)
	}
}

// A contract that lost its code stays acceptable after review: same address
// and type, so the plausibility check does not apply.
func TestWatchAcceptContractThatLostItsCodeIsNotBlocked(t *testing.T) {
	chain := newFakeChain(t)
	chain.code = "0x6080"
	t.Setenv("ADK_T_RPC_A", chain.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", chain.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "token", addr: testWallet, typ: "contract", envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	chain.setCode("0x")
	if code, _, _ := w.run("check"); code != 1 {
		t.Fatalf("check: code=%d", code)
	}
	if code, out, errs := w.run("accept", "token", "--note", "검토함"); code != 0 {
		t.Fatalf("accept: code=%d\n%s\n%s", code, out, errs)
	}
}

type staleFinding struct {
	ID, Location, Evidence, Title, Confidence string
	Severity                                  any
}

func staleFindings(t *testing.T, js string) []staleFinding {
	t.Helper()
	var r struct{ Findings []staleFinding }
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, js)
	}
	return r.Findings
}

// N3: the baseline holds new owners and a node far behind returns the old ones.
func staleSafe(t *testing.T) (*wsp, *fakeChain) {
	w, c := safeChain(t)
	mustInit(t, w)
	c.mu.Lock()
	c.calls = map[string]string{selOwners: ownersRet(testDelA), selThreshold: "0x" + strings.Repeat("0", 63) + "2"}
	c.blockAge = 48 * time.Hour
	c.mu.Unlock()
	return w, c
}

func TestWatchStaleNodeFindingIsNotCertain(t *testing.T) {
	w, _ := staleSafe(t)
	code, js, errs := w.run("check", "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	fs := staleFindings(t, js)
	if len(fs) != 1 || fs[0].ID != "WA-002" || fs[0].Severity != "critical" {
		t.Fatalf("the alert must stay: %+v", fs)
	}
	f := fs[0]
	if f.Confidence != "suspect" {
		t.Errorf("confidence = %q, want suspect", f.Confidence)
	}
	if !strings.Contains(f.Title, "멈춘 것으로 보이는 노드") || !strings.Contains(f.Evidence, "노드 상태를 먼저 확인하세요") || !strings.Contains(f.Evidence, "owners") {
		t.Errorf("title = %q evidence = %q", f.Title, f.Evidence)
	}
	if strings.Contains(f.Title, "바뀌었습니다") {
		t.Errorf("the title still states the change as a fact: %q", f.Title)
	}
}

func TestWatchStaleNodeAcceptIsRefused(t *testing.T) {
	w, _ := staleSafe(t)
	before := readFile(t, w.base)
	if code, _, _ := w.run("accept", "vault", "--note", "x"); code != 2 {
		t.Errorf("accept on a stale node: code=%d", code)
	}
	if readFile(t, w.base) != before || fileExists(w.history) {
		t.Error("a refused accept changed something")
	}
}

func TestWatchStaleNodeWebhookCarriesTheSignal(t *testing.T) {
	w, _ := staleSafe(t)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)
	if code, _, errs := w.run("check"); code != 1 {
		t.Fatalf("code=%d %s", code, errs)
	}
	bodies := h.all()
	if len(bodies) != 1 {
		t.Fatalf("bodies = %v", bodies)
	}
	var p struct {
		Findings     []struct{ Key, ID, Severity, Confidence string }
		StaleTargets []string `json:"stale_targets"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Findings) != 1 || p.Findings[0].Confidence != "suspect" || p.Findings[0].ID != "WA-002" || p.Findings[0].Severity != "critical" {
		t.Errorf("payload = %s", bodies[0])
	}
	if len(p.StaleTargets) != 1 || p.StaleTargets[0] != "vault" {
		t.Errorf("stale_targets = %v in %s", p.StaleTargets, bodies[0])
	}
	if strings.Contains(bodies[0], "http") || strings.Contains(bodies[0], "127.0.0.1") {
		t.Errorf("the body must hold no address: %s", bodies[0])
	}
}

// Every webhook body has the new fields, even a certain finding.
func TestWebhookBodyHasConfidenceAndStaleTargets(t *testing.T) {
	w, chain := oneWallet(t)
	mustInit(t, w)
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)
	chain.setCode(delegationCode(testDelA))
	if code, _, _ := w.run("check"); code != 1 {
		t.Fatal(code)
	}
	b := h.all()[0]
	if !strings.Contains(b, `"confidence":"certain"`) || !strings.Contains(b, `"stale_targets":[]`) {
		t.Errorf("body = %s", b)
	}
}

// A partial read that is not a stale node keeps the fields it read certain.
func TestWatchSafeTakeoverStaysCertain(t *testing.T) {
	w, c := safeChain(t)
	mustInit(t, w)
	c.mu.Lock()
	c.slots["0x0"] = "0x" + addrWordT(testDelB)
	c.calls = map[string]string{}
	c.mu.Unlock()
	h, url := newHook(t, 0)
	t.Setenv("ADK_WATCH_WEBHOOK", url)
	code, js, _ := w.run("check", "--format", "json")
	fs := staleFindings(t, js)
	if code != 1 || len(fs) != 1 || fs[0].Confidence != "certain" || strings.Contains(fs[0].Title+fs[0].Evidence, "멈춘") {
		t.Fatalf("code=%d findings=%+v", code, fs)
	}
	b := h.all()[0]
	if !strings.Contains(b, `"confidence":"certain"`) || !strings.Contains(b, `"stale_targets":[]`) {
		t.Errorf("body = %s", b)
	}
}
