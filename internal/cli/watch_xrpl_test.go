package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The answers below follow the documented XRPL JSON-RPC formats. They have not
// been checked against a live server.

const xrplAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// xrplAddr makes a valid but invented classic address from a seed.
func xrplAddr(seed byte) string {
	p := make([]byte, 21)
	for i := 1; i < 21; i++ {
		p[i] = seed + byte(i)
	}
	h1 := sha256.Sum256(p)
	h2 := sha256.Sum256(h1[:])
	full := append(p, h2[:4]...)
	n := new(big.Int).SetBytes(full)
	var out []byte
	base, mod := big.NewInt(58), new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, xrplAlphabet[mod.Int64()])
	}
	out = append(out, xrplAlphabet[0]) // the version byte is zero
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

type fakeXRPL struct {
	mu      sync.Mutex
	acct    string
	regKey  string
	flags   int
	objects string // account_objects as JSON; empty means none
	status  int
	srv     *httptest.Server
}

func newFakeXRPL(t *testing.T, acct string) *fakeXRPL {
	t.Helper()
	f := &fakeXRPL{acct: acct}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var res string
		switch req.Method {
		case "account_info":
			rk := ""
			if f.regKey != "" {
				rk = `,"RegularKey":"` + f.regKey + `"`
			}
			res = fmt.Sprintf(`{"account_data":{"Account":"%s","Flags":%d,"LedgerEntryType":"AccountRoot"%s},"ledger_index":77,"validated":true,"status":"success"}`, f.acct, f.flags, rk)
		case "account_objects":
			objs := f.objects
			if objs == "" {
				objs = "[]"
			}
			res = fmt.Sprintf(`{"account":"%s","account_objects":%s,"ledger_index":77,"validated":true,"status":"success"}`, f.acct, objs)
		case "ledger":
			res = fmt.Sprintf(`{"ledger":{"close_time":%d},"ledger_index":77,"validated":true,"status":"success"}`, time.Now().Unix()-946684800)
		default:
			res = `{"status":"error","error":"unknownCmd"}`
		}
		_, _ = w.Write([]byte(`{"result":` + res + `}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeXRPL) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func xrplWsp(t *testing.T, acct string, envs string) *wsp {
	t.Helper()
	w := newWsp(t)
	cfg := fmt.Sprintf("targets:\n  - key: xrp-hot\n    kind: xrpl-wallet\n    options:\n      address: \"%s\"\n      rpc_url_env: \"%s\"\n", acct, envs)
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWatchXRPLInitCheckAndRegularKey(t *testing.T) {
	acct := xrplAddr(1)
	f := newFakeXRPL(t, acct)
	t.Setenv("ADK_X_RPC_A", f.srv.URL+"/a")
	t.Setenv("ADK_X_RPC_B", f.srv.URL+"/b")
	w := xrplWsp(t, acct, "ADK_X_RPC_A,ADK_X_RPC_B")
	mustInit(t, w)
	if code, out, errs := w.run("check"); code != 0 {
		t.Fatalf("unchanged check = %d\n%s\n%s", code, out, errs)
	}

	key := xrplAddr(9)
	f.set(func() { f.regKey = key })
	code, js, errs := w.run("check", "--format", "json")
	if code != 1 {
		t.Fatalf("check = %d\n%s\n%s", code, js, errs)
	}
	fs := staleFindings(t, js)
	if len(fs) != 1 || fs[0].ID != "WA-002" || fs[0].Severity != "critical" || fs[0].Location != "xrp-hot" {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(fs[0].Evidence, "regular_key") || !strings.Contains(fs[0].Evidence, key) {
		t.Errorf("evidence = %q", fs[0].Evidence)
	}

	// A different flag word is the same kind of change.
	f.set(func() { f.regKey = ""; f.flags = 1 << 20 })
	code, js, _ = w.run("check", "--format", "json")
	if fs := staleFindings(t, js); code != 1 || len(fs) != 1 || fs[0].ID != "WA-002" || !strings.Contains(fs[0].Evidence, "flags") {
		t.Fatalf("flags: code=%d %+v", code, fs)
	}
}

func TestWatchXRPLRPCDownIsExitTwo(t *testing.T) {
	acct := xrplAddr(1)
	f := newFakeXRPL(t, acct)
	t.Setenv("ADK_X_RPC_A", f.srv.URL+"/a")
	t.Setenv("ADK_X_RPC_B", f.srv.URL+"/b")
	w := xrplWsp(t, acct, "ADK_X_RPC_A,ADK_X_RPC_B")
	mustInit(t, w)
	f.set(func() { f.status = 500 })
	code, out, errs := w.run("check")
	if code != 2 {
		t.Fatalf("check = %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out+errs, "xrp-hot") {
		t.Errorf("the unverified target is not named:\n%s\n%s", out, errs)
	}
	// And init refuses to write a baseline from an unreadable node.
	w2 := xrplWsp(t, acct, "ADK_X_RPC_A,ADK_X_RPC_B")
	if code, _, _ := w2.run("init"); code != 2 {
		t.Errorf("init with the node down = %d", code)
	}
	if fileExists(w2.base) {
		t.Error("init wrote a baseline")
	}
}

func TestWatchXRPLInitRefusesAWrongAddress(t *testing.T) {
	acct := xrplAddr(1)
	f := newFakeXRPL(t, acct)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"status":"error","error":"actNotFound","error_message":"Account not found."}}`))
	})
	t.Setenv("ADK_X_RPC_A", f.srv.URL)
	w := xrplWsp(t, acct, "ADK_X_RPC_A")
	code, _, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "xrp-hot") || !strings.Contains(errs, "actNotFound") || fileExists(w.base) {
		t.Fatalf("init = %d\n%s", code, errs)
	}
}

func TestWatchXRPLBadAddressIsAConfigError(t *testing.T) {
	w := xrplWsp(t, "rThisIsNotAnAddress", "ADK_X_RPC_A")
	code, _, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "address") || strings.Contains(errs, "rThisIsNotAnAddress") {
		t.Fatalf("init = %d\n%s", code, errs)
	}
}

func TestWatchXRPLNotesForSingleEndpoint(t *testing.T) {
	acct := xrplAddr(1)
	f := newFakeXRPL(t, acct)
	t.Setenv("ADK_X_RPC_A", f.srv.URL)
	w := xrplWsp(t, acct, "ADK_X_RPC_A")
	code, _, errs := w.run("init")
	if code != 0 || !strings.Contains(errs, singleRPCNote) {
		t.Fatalf("init = %d\n%s", code, errs)
	}
}
