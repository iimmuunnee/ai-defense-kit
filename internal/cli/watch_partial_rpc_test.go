package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// deadRPC returns the address of a server that has been shut down.
func deadRPC(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	u := s.URL + "/secret-path"
	s.Close()
	return u
}

// twoRPCWallet is a wallet read through RPC A (a live fake chain) and RPC B,
// which the test can take down. The baseline is made while both are up.
func twoRPCWallet(t *testing.T) (*wsp, *fakeChain) {
	t.Helper()
	c := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", c.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", c.srv.URL+"/b")
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	mustInit(t, w)
	return w, c
}

func TestWatchOneRPCDownStillReportsDelegation(t *testing.T) {
	w, c := twoRPCWallet(t)
	c.setCode(delegationCode(testDelA))
	t.Setenv("ADK_T_RPC_B", deadRPC(t))
	code, out, errs := w.run("check")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "WA-001") || !strings.Contains(out, "critical") && !strings.Contains(out, "치명") {
		t.Errorf("the delegation must be reported:\n%s", out)
	}
	if !strings.Contains(out, "RPC 2") || !strings.Contains(out, "교차 확인 못 함") {
		t.Errorf("the missing RPC must be named:\n%s", out)
	}
	for _, s := range []string{"127.0.0.1", "secret-path", "http://"} {
		if strings.Contains(out, s) || strings.Contains(errs, s) {
			t.Errorf("output holds an address fragment %q:\n%s\n%s", s, out, errs)
		}
	}
}

func TestWatchOneRPCDownNoChangeIsUnverified(t *testing.T) {
	w, _ := twoRPCWallet(t)
	t.Setenv("ADK_T_RPC_B", deadRPC(t))
	code, out, errs := w.run("check")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, "WA-0") {
		t.Errorf("nothing changed, no finding expected:\n%s", out)
	}
	if !strings.Contains(out, "RPC 2") {
		t.Errorf("the missing RPC must be named:\n%s", out)
	}
}

func TestWatchInitRefusesPartialRPC(t *testing.T) {
	c := newFakeChain(t)
	t.Setenv("ADK_T_RPC_A", c.srv.URL+"/a")
	t.Setenv("ADK_T_RPC_B", deadRPC(t))
	w := newWsp(t, wTarget{key: "hot", addr: testWallet, envs: "ADK_T_RPC_A,ADK_T_RPC_B"})
	code, out, errs := w.run("init")
	if code != 2 {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "RPC 2") || !strings.Contains(errs, "기준값을 만들지 않았습니다") {
		t.Errorf("the message must name the missing RPC and say no baseline was made:\n%s", errs)
	}
	if fileExists(w.base) {
		t.Error("a baseline was written from one endpoint")
	}
	for _, s := range []string{"127.0.0.1", "secret-path"} {
		if strings.Contains(errs, s) {
			t.Errorf("stderr holds an address fragment %q", s)
		}
	}
}

func TestWatchXRPLOneRPCDownStillReportsRegularKey(t *testing.T) {
	acct := xrplAddr(1)
	f := newFakeXRPL(t, acct)
	t.Setenv("ADK_X_RPC_A", f.srv.URL+"/a")
	t.Setenv("ADK_X_RPC_B", f.srv.URL+"/b")
	w := xrplWsp(t, acct, "ADK_X_RPC_A,ADK_X_RPC_B")
	mustInit(t, w)
	key := xrplAddr(9)
	f.set(func() { f.regKey = key })
	t.Setenv("ADK_X_RPC_B", deadRPC(t))
	code, out, errs := w.run("check")
	if code != 1 || !strings.Contains(out, "WA-002") || !strings.Contains(out, "RPC 2") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, "127.0.0.1") || strings.Contains(out, "secret-path") {
		t.Errorf("output holds an address fragment:\n%s", out)
	}

	// Nothing changed: the second node is still missing, so exit 2.
	f.set(func() { f.regKey = "" })
	if code, out, _ := w.run("check"); code != 2 || !strings.Contains(out, "RPC 2") {
		t.Errorf("no change, one down: code=%d\n%s", code, out)
	}
	// And init refuses a baseline from one node.
	w2 := xrplWsp(t, acct, "ADK_X_RPC_A,ADK_X_RPC_B")
	code, _, errs = w2.run("init")
	if code != 2 || !strings.Contains(errs, "RPC 2") || fileExists(w2.base) {
		t.Errorf("init: code=%d base=%v\n%s", code, fileExists(w2.base), errs)
	}
}

func TestWatchOneRPCDownStaleNodeIsStillStale(t *testing.T) {
	w, c := twoRPCWallet(t)
	c.setCode(delegationCode(testDelA))
	c.mu.Lock()
	c.blockAge = 48 * 3600 * 1e9
	c.mu.Unlock()
	t.Setenv("ADK_T_RPC_B", deadRPC(t))
	code, js, errs := w.run("check", "--format", "json")
	if code != 1 {
		t.Fatalf("code=%d\n%s\n%s", code, js, errs)
	}
	fs := staleFindings(t, js)
	if len(fs) != 1 || fs[0].Confidence != "suspect" {
		t.Fatalf("a stale answering node must still lower confidence: %+v", fs)
	}
}

func TestWatchAcceptRefusesPartialRPC(t *testing.T) {
	w, c := twoRPCWallet(t)
	c.setCode(delegationCode(testDelA))
	t.Setenv("ADK_T_RPC_B", deadRPC(t))
	before := readFile(t, w.base)
	if code, _, errs := w.run("accept", "hot", "--note", "x"); code != 2 || !strings.Contains(errs, "RPC 2") {
		t.Errorf("accept from one node: code=%d\n%s", code, errs)
	}
	if readFile(t, w.base) != before {
		t.Error("a refused accept changed the baseline")
	}
}
