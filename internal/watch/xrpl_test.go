package watch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch/rpc"
)

// The fake responses below follow the XRPL JSON-RPC formats as documented
// (account_info, account_objects, ledger). They have not been checked against a
// live server.

const xAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// xEncode builds a classic address from a 21-byte payload (version + account
// ID): base58 with the XRPL alphabet and a double SHA-256 checksum.
func xEncode(payload []byte) string {
	h1 := sha256.Sum256(payload)
	h2 := sha256.Sum256(h1[:])
	full := append(append([]byte{}, payload...), h2[:4]...)
	n := new(big.Int).SetBytes(full)
	var out []byte
	base, mod := big.NewInt(58), new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, xAlphabet[mod.Int64()])
	}
	for _, b := range full {
		if b != 0 {
			break
		}
		out = append(out, xAlphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// xAddr makes a valid but invented address from a seed.
func xAddr(seed byte) string {
	p := make([]byte, 21)
	for i := 1; i < 21; i++ {
		p[i] = seed + byte(i)
	}
	return xEncode(p)
}

type xsigner struct {
	acct string
	w    int
}

type xlist struct {
	quorum  int
	signers []xsigner
}

func (l xlist) json() map[string]any {
	var entries []any
	for _, s := range l.signers {
		entries = append(entries, map[string]any{"SignerEntry": map[string]any{"Account": s.acct, "SignerWeight": s.w}})
	}
	return map[string]any{"LedgerEntryType": "SignerList", "SignerQuorum": l.quorum, "SignerEntries": entries, "SignerListID": 0, "Flags": 0}
}

// xnode answers like an XRPL server, from fixed values.
type xnode struct {
	mu          sync.Mutex
	account     string
	regKey      string
	flags       int
	lists       []xlist
	pages       [][]xlist // when set, account_objects is served in pages
	endless     bool      // every account_objects page has a marker
	ledgerIndex int
	notValidInf bool
	notValidObj bool
	notValidLed bool
	closeTime   string // raw JSON for close_time; "" means now
	now         func() time.Time
	raw         map[string]string // method -> whole answer body
	status      int
	reqs        []map[string]any
	infoCalls   int
}

func newXNode(account string) *xnode {
	return &xnode{account: account, ledgerIndex: 1000, now: fixedNow}
}

func fixedNow() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }

func rippleSeconds(t time.Time) int64 { return t.Unix() - 946684800 }

func (n *xnode) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(n.handle))
	t.Cleanup(srv.Close)
	return srv
}

func ok(v map[string]any) string {
	v["status"] = "success"
	b, _ := json.Marshal(map[string]any{"result": v})
	return string(b)
}

func (n *xnode) handle(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var req struct {
		Method string           `json:"method"`
		Params []map[string]any `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	rec := map[string]any{"method": req.Method}
	if len(req.Params) > 0 {
		rec["params"] = req.Params[0]
	}
	n.reqs = append(n.reqs, rec)
	if n.status != 0 {
		w.WriteHeader(n.status)
		return
	}
	if body, has := n.raw[req.Method]; has {
		_, _ = w.Write([]byte(body))
		return
	}
	var p map[string]any
	if len(req.Params) > 0 {
		p = req.Params[0]
	}
	switch req.Method {
	case "account_info":
		n.infoCalls++
		data := map[string]any{"Account": n.account, "Flags": n.flags, "LedgerEntryType": "AccountRoot", "Balance": "100000000", "Sequence": 5}
		if n.regKey != "" {
			data["RegularKey"] = n.regKey
		}
		_, _ = w.Write([]byte(ok(map[string]any{"account_data": data, "ledger_index": n.ledgerIndex, "validated": !n.notValidInf})))
	case "account_objects":
		page, lists := 0, n.lists
		if n.pages != nil {
			if m, has := p["marker"].(string); has {
				fmt.Sscanf(m, "m%d", &page)
			}
			lists = n.pages[min(page, len(n.pages)-1)]
		}
		objs := []any{}
		for _, l := range lists {
			objs = append(objs, l.json())
		}
		res := map[string]any{"account": n.account, "account_objects": objs, "ledger_index": n.ledgerIndex, "validated": !n.notValidObj}
		if n.endless || (n.pages != nil && page+1 < len(n.pages)) {
			res["marker"] = fmt.Sprintf("m%d", page+1)
		}
		_, _ = w.Write([]byte(ok(res)))
	case "ledger":
		ct := n.closeTime
		if ct == "" {
			ct = fmt.Sprint(rippleSeconds(n.now()))
		}
		body := `{"result":{"ledger":{"close_time":` + ct + `,"ledger_index":"1000","closed":true},"ledger_index":1000,"validated":` + fmt.Sprint(!n.notValidLed) + `,"status":"success"}}`
		_, _ = w.Write([]byte(body))
	default:
		_, _ = w.Write([]byte(`{"result":{"status":"error","error":"unknownCmd"}}`))
	}
}

func (n *xnode) setMu(f func()) { n.mu.Lock(); f(); n.mu.Unlock() }

func (n *xnode) methods() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, r := range n.reqs {
		out = append(out, r["method"].(string))
	}
	return out
}

func xopts(addr string) map[string]any { return map[string]any{"address": addr} }

func xobserver(urls ...string) *xrplObserver {
	o := newXRPLObserver(func(Target) *rpc.Client { return rpc.New(urls, nil) }, 0)
	o.now = fixedNow
	return o
}

func xobserve(t *testing.T, opts map[string]any, urls ...string) (Observation, error) {
	t.Helper()
	return xobserver(urls...).Observe(context.Background(), Target{Key: "x", Kind: kindXRPL, Options: opts})
}

func xmust(t *testing.T, opts map[string]any, urls ...string) Observation {
	t.Helper()
	obs, err := xobserve(t, opts, urls...)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func TestXRPLKind(t *testing.T) {
	if NewXRPLObserver(clientFor()).Kind() != "xrpl-wallet" {
		t.Fatal("kind")
	}
	if !knownKinds["xrpl-wallet"] {
		t.Fatal("knownKinds")
	}
}

func TestXRPLFields(t *testing.T) {
	acct, key := xAddr(1), xAddr(2)
	s1, s2, s3 := xAddr(30), xAddr(10), xAddr(20)
	n := newXNode(acct)
	n.regKey = key
	n.flags = 0x00100000 // an invented value; not interpreted
	n.lists = []xlist{{quorum: 3, signers: []xsigner{{s1, 1}, {s2, 2}, {s3, 1}}}}
	obs := xmust(t, xopts(acct), n.server(t).URL)

	want := map[string]string{
		"address":     acct,
		"regular_key": key,
		"flags":       "1048576",
	}
	for k, v := range want {
		if obs[k] != v {
			t.Errorf("%s = %q, want %q", k, obs[k], v)
		}
	}
	// Sorted by account, whatever the order the server used.
	signers := []xsigner{{s1, 1}, {s2, 2}, {s3, 1}}
	sortSigners(signers)
	var parts []string
	for _, s := range signers {
		parts = append(parts, fmt.Sprintf("%s:%d", s.acct, s.w))
	}
	if got, w := obs["signer_list"], "quorum=3;"+strings.Join(parts, ","); got != w {
		t.Errorf("signer_list = %q, want %q", got, w)
	}
	if !(obs["signer_list"] > "") || strings.Index(obs["signer_list"], s2) > strings.Index(obs["signer_list"], s3) {
		t.Errorf("signers are not sorted by account: %q", obs["signer_list"])
	}

	// What was asked: validated ledger, the signer_list type, the account.
	n.mu.Lock()
	defer n.mu.Unlock()
	seen := map[string]bool{}
	for _, r := range n.reqs {
		m, p := r["method"].(string), r["params"].(map[string]any)
		seen[m] = true
		if p["ledger_index"] != "validated" {
			t.Errorf("%s: ledger_index = %v", m, p["ledger_index"])
		}
		if m == "account_objects" && (p["type"] != "signer_list" || p["account"] != acct) {
			t.Errorf("account_objects params = %v", p)
		}
		if m == "account_info" && p["account"] != acct {
			t.Errorf("account_info params = %v", p)
		}
	}
	if !seen["account_info"] || !seen["account_objects"] {
		t.Errorf("methods = %v", seen)
	}
}

func sortSigners(s []xsigner) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j].acct < s[i].acct {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

func TestXRPLEmptyFieldsArePresent(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	obs := xmust(t, xopts(acct), n.server(t).URL)
	for _, k := range []string{"address", "regular_key", "signer_list", "flags"} {
		if _, has := obs[k]; !has {
			t.Errorf("%s missing", k)
		}
	}
	if obs["regular_key"] != "" || obs["signer_list"] != "" || obs["flags"] != "0" {
		t.Errorf("obs = %v", obs)
	}
}

func TestXRPLMultipleSignerListsCombineStably(t *testing.T) {
	acct := xAddr(1)
	a, b := xAddr(40), xAddr(50)
	l1 := xlist{quorum: 2, signers: []xsigner{{a, 1}, {b, 1}}}
	l2 := xlist{quorum: 1, signers: []xsigner{{b, 1}}}
	n1 := newXNode(acct)
	n1.lists = []xlist{l1, l2}
	n2 := newXNode(acct)
	n2.lists = []xlist{l2, l1}
	o1 := xmust(t, xopts(acct), n1.server(t).URL)
	o2 := xmust(t, xopts(acct), n2.server(t).URL)
	if o1["signer_list"] != o2["signer_list"] || !strings.Contains(o1["signer_list"], "quorum=1;") || !strings.Contains(o1["signer_list"], "quorum=2;") {
		t.Errorf("%q vs %q", o1["signer_list"], o2["signer_list"])
	}
}

func TestXRPLNotValidated(t *testing.T) {
	acct := xAddr(1)
	for name, set := range map[string]func(*xnode){
		"account_info":    func(n *xnode) { n.notValidInf = true },
		"account_objects": func(n *xnode) { n.notValidObj = true },
	} {
		n := newXNode(acct)
		set(n)
		obs, err := xobserve(t, xopts(acct), n.server(t).URL)
		if err == nil || obs != nil {
			t.Errorf("%s: validated:false must be an error, got obs=%v err=%v", name, obs, err)
		}
		var pe PartialError
		if !errors.As(err, &pe) || pe.Obs["address"] != acct {
			t.Errorf("%s: want a PartialError holding the address: %v", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "validated") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A missing "validated" field is not validated either.
	n := newXNode(acct)
	n.raw = map[string]string{"account_info": ok(map[string]any{"account_data": map[string]any{"Account": acct, "Flags": 0}, "ledger_index": 5})}
	if _, err := xobserve(t, xopts(acct), n.server(t).URL); err == nil {
		t.Error("missing validated must be an error")
	}
}

func TestXRPLActNotFound(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.raw = map[string]string{"account_info": `{"result":{"status":"error","error":"actNotFound","error_code":19,"error_message":"Account not found.","request":{"command":"account_info"}}}`}
	obs, err := xobserve(t, xopts(acct), n.server(t).URL)
	if err == nil || obs != nil {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	if !strings.Contains(err.Error(), "x") || !strings.Contains(err.Error(), "actNotFound") || !strings.Contains(err.Error(), "주소") || !strings.Contains(err.Error(), "잘못") {
		t.Errorf("the message must name the target and say the address may be wrong: %v", err)
	}
	if strings.Contains(err.Error(), "Account not found") {
		t.Errorf("server text echoed: %v", err)
	}
}

func TestXRPLErrorStatusAndGarbage(t *testing.T) {
	acct := xAddr(1)
	const leak = "SECRETKEY123"
	cases := map[string]func(*xnode){
		"status error": func(n *xnode) {
			n.raw = map[string]string{"account_info": `{"result":{"status":"error","error":"` + leak + `","error_message":"` + leak + `"}}`}
		},
		"status missing": func(n *xnode) {
			n.raw = map[string]string{"account_info": `{"result":{"account_data":{"Account":"` + acct + `","Flags":0},"validated":true}}`}
		},
		"html":          func(n *xnode) { n.raw = map[string]string{"account_info": "<html>" + leak + "</html>"} },
		"http 500":      func(n *xnode) { n.status = 500 },
		"no result":     func(n *xnode) { n.raw = map[string]string{"account_info": `{"error":"` + leak + `"}`} },
		"result string": func(n *xnode) { n.raw = map[string]string{"account_info": `{"result":"` + leak + `"}`} },
		"empty body":    func(n *xnode) { n.raw = map[string]string{"account_info": ``} },
		"no flags": func(n *xnode) {
			n.raw = map[string]string{"account_info": ok(map[string]any{"account_data": map[string]any{"Account": acct}, "validated": true})}
		},
		"negative flags": func(n *xnode) {
			n.raw = map[string]string{"account_info": ok(map[string]any{"account_data": map[string]any{"Account": acct, "Flags": -1}, "validated": true})}
		},
		"flags text": func(n *xnode) {
			n.raw = map[string]string{"account_info": ok(map[string]any{"account_data": map[string]any{"Account": acct, "Flags": leak}, "validated": true})}
		},
		"other account": func(n *xnode) {
			n.raw = map[string]string{"account_info": ok(map[string]any{"account_data": map[string]any{"Account": xAddr(9), "Flags": 0}, "validated": true})}
		},
		"bad regular key": func(n *xnode) { n.regKey = "r" + leak },
		"objects other account": func(n *xnode) {
			n.raw = map[string]string{"account_objects": ok(map[string]any{"account": xAddr(9), "account_objects": []any{}, "ledger_index": 1, "validated": true})}
		},
		"objects error": func(n *xnode) {
			n.raw = map[string]string{"account_objects": `{"result":{"status":"error","error":"invalidParams","error_message":"` + leak + `"}}`}
		},
		"foreign object": func(n *xnode) {
			n.raw = map[string]string{"account_objects": ok(map[string]any{"account": acct, "ledger_index": 1, "validated": true,
				"account_objects": []any{map[string]any{"LedgerEntryType": "Escrow"}}})}
		},
		"signer without quorum": func(n *xnode) {
			n.raw = map[string]string{"account_objects": ok(map[string]any{"account": acct, "ledger_index": 1, "validated": true,
				"account_objects": []any{map[string]any{"LedgerEntryType": "SignerList", "SignerEntries": []any{}}}})}
		},
		"bad signer account": func(n *xnode) {
			n.lists = []xlist{{quorum: 1, signers: []xsigner{{"rNotAnAddress" + leak, 1}}}}
		},
	}
	for name, set := range cases {
		n := newXNode(acct)
		set(n)
		obs, err := xobserve(t, xopts(acct), n.server(t).URL)
		if err == nil || obs != nil {
			t.Errorf("%s: want an error, got obs=%v err=%v", name, obs, err)
			continue
		}
		if strings.Contains(err.Error(), leak) {
			t.Errorf("%s: server text echoed: %v", name, err)
		}
		var pe PartialError
		if !errors.As(err, &pe) {
			t.Errorf("%s: want a PartialError: %v", name, err)
		}
	}
}

func TestXRPLPartialKeepsWhatWasRead(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.regKey = xAddr(2)
	n.flags = 7
	n.notValidObj = true
	_, err := xobserve(t, xopts(acct), n.server(t).URL)
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}
	if pe.Obs["regular_key"] != n.regKey || pe.Obs["flags"] != "7" {
		t.Errorf("read fields were dropped: %v", pe.Obs)
	}
	if _, has := pe.Obs["signer_list"]; has {
		t.Errorf("an unread field must be absent, not empty: %v", pe.Obs)
	}
}

func TestXRPLPaginationFollowed(t *testing.T) {
	acct := xAddr(1)
	a, b := xAddr(40), xAddr(50)
	n := newXNode(acct)
	n.pages = [][]xlist{
		{{quorum: 2, signers: []xsigner{{a, 1}}}},
		{{quorum: 1, signers: []xsigner{{b, 1}}}},
	}
	obs := xmust(t, xopts(acct), n.server(t).URL)
	if !strings.Contains(obs["signer_list"], "quorum=2;"+a) || !strings.Contains(obs["signer_list"], "quorum=1;"+b) {
		t.Errorf("signer_list = %q", obs["signer_list"])
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var second map[string]any
	for _, r := range n.reqs {
		if r["method"] == "account_objects" {
			if p := r["params"].(map[string]any); p["marker"] != nil {
				second = p
			}
		}
	}
	if second == nil || second["marker"] != "m1" {
		t.Fatalf("the marker was not followed: %v", n.reqs)
	}
	// Both pages come from the same ledger.
	if idx, _ := second["ledger_index"].(float64); idx != 1000 {
		t.Errorf("the second page must pin the ledger of the first: %v", second["ledger_index"])
	}
}

func TestXRPLPaginationOverLimitIsAnError(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.endless = true
	n.lists = []xlist{{quorum: 1, signers: []xsigner{{xAddr(40), 1}}}}
	obs, err := xobserve(t, xopts(acct), n.server(t).URL)
	if err == nil || obs != nil {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatal(err)
	}
	if _, has := pe.Obs["signer_list"]; has {
		t.Errorf("a truncated list must not be returned as a value: %v", pe.Obs)
	}
	count := 0
	for _, m := range n.methods() {
		if m == "account_objects" {
			count++
		}
	}
	if count != maxSignerPages {
		t.Errorf("asked %d pages, limit is %d", count, maxSignerPages)
	}
}

func TestXRPLDisagreement(t *testing.T) {
	acct := xAddr(1)
	a, b := newXNode(acct), newXNode(acct)
	b.regKey = xAddr(2)
	o := xobserver(a.server(t).URL, b.server(t).URL)
	_, err := o.Observe(context.Background(), Target{Key: "x", Kind: kindXRPL, Options: xopts(acct)})
	if !errors.Is(err, rpc.ErrDisagree) {
		t.Fatalf("err = %v", err)
	}
	// Asked twice: the second time is the retry.
	for _, nn := range []*xnode{a, b} {
		nn.mu.Lock()
		if nn.infoCalls != 2 {
			t.Errorf("account_info asked %d times", nn.infoCalls)
		}
		nn.mu.Unlock()
	}
	var pe PartialError
	if !errors.As(err, &pe) || pe.Obs["address"] != acct {
		t.Errorf("want a PartialError with the address: %v", err)
	}
}

func TestXRPLDisagreementAboutSignersIsRetried(t *testing.T) {
	acct := xAddr(1)
	a, b := newXNode(acct), newXNode(acct)
	a.lists = []xlist{{quorum: 1, signers: []xsigner{{xAddr(40), 1}}}}
	b.lists = []xlist{{quorum: 2, signers: []xsigner{{xAddr(40), 1}, {xAddr(50), 1}}}}
	_, err := xobserve(t, xopts(acct), a.server(t).URL, b.server(t).URL)
	if !errors.Is(err, rpc.ErrDisagree) {
		t.Fatalf("err = %v", err)
	}
}

func TestXRPLDisagreementThatClearsOnRetry(t *testing.T) {
	acct := xAddr(1)
	good, lag := newXNode(acct), newXNode(acct)
	good.regKey = xAddr(2)
	// The second server is behind on the first question only.
	var calls int
	var mu sync.Mutex
	laggard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(data))
		mu.Lock()
		c := calls
		if strings.Contains(string(data), "account_info") {
			calls++
		}
		mu.Unlock()
		if c == 0 {
			lag.handle(w, r) // no regular key yet
			return
		}
		good.handle(w, r)
	}))
	defer laggard.Close()
	obs, err := xobserve(t, xopts(acct), good.server(t).URL, laggard.URL)
	if err != nil {
		t.Fatal(err)
	}
	if obs["regular_key"] != good.regKey {
		t.Errorf("obs = %v", obs)
	}
}

func TestXRPLDifferentLedgersSameFieldsAgree(t *testing.T) {
	acct := xAddr(1)
	a, b := newXNode(acct), newXNode(acct)
	for _, n := range []*xnode{a, b} {
		n.regKey = xAddr(2)
		n.flags = 3
		n.lists = []xlist{{quorum: 1, signers: []xsigner{{xAddr(40), 1}}}}
	}
	a.ledgerIndex, b.ledgerIndex = 1000, 1003
	obs, err := xobserve(t, xopts(acct), a.server(t).URL, b.server(t).URL)
	if err != nil {
		t.Fatalf("different ledger indexes with the same fields must agree: %v", err)
	}
	if obs["regular_key"] != a.regKey {
		t.Errorf("obs = %v", obs)
	}
	// And no retry was needed.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.infoCalls != 1 {
		t.Errorf("account_info asked %d times", a.infoCalls)
	}
}

func TestXRPLStaleLedger(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.regKey = xAddr(2)
	n.closeTime = fmt.Sprint(rippleSeconds(fixedNow().Add(-2 * time.Hour)))
	obs, err := xobserve(t, xopts(acct), n.server(t).URL)
	if obs != nil || !errors.Is(err, ErrStale) {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	var pe PartialError
	if !errors.As(err, &pe) || pe.Obs["regular_key"] != n.regKey || pe.Obs["flags"] != "0" {
		t.Errorf("read fields must be kept: %v", err)
	}
	if !strings.Contains(err.Error(), "RPC 1") {
		t.Errorf("the message must say which RPC: %v", err)
	}

	// Within the limit.
	n.setMu(func() { n.closeTime = fmt.Sprint(rippleSeconds(fixedNow().Add(-10 * time.Minute))) })
	if _, err := xobserve(t, xopts(acct), n.server(t).URL); err != nil {
		t.Errorf("10 minutes old with the default 15m: %v", err)
	}
	// Turned off.
	n.setMu(func() { n.closeTime = fmt.Sprint(rippleSeconds(fixedNow().Add(-48 * time.Hour))) })
	o := xopts(acct)
	o["max_block_age"] = "0"
	if _, err := xobserve(t, o, n.server(t).URL); err != nil {
		t.Errorf("max_block_age 0: %v", err)
	}
	// A custom limit.
	o["max_block_age"] = "1h"
	if _, err := xobserve(t, o, n.server(t).URL); !errors.Is(err, ErrStale) {
		t.Errorf("48h old with 1h: %v", err)
	}
}

func TestXRPLFutureLedgerIsNotFresh(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.closeTime = fmt.Sprint(rippleSeconds(fixedNow().Add(2 * time.Hour)))
	obs, err := xobserve(t, xopts(acct), n.server(t).URL)
	if obs != nil || err == nil {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	if errors.Is(err, ErrStale) {
		t.Errorf("a ledger from the future is not a stopped node: %v", err)
	}
	var pe PartialError
	if !errors.As(err, &pe) || pe.Obs["flags"] != "0" {
		t.Errorf("read fields must be kept: %v", err)
	}
	// A small skew is fine.
	n.setMu(func() { n.closeTime = fmt.Sprint(rippleSeconds(fixedNow().Add(time.Minute))) })
	if _, err := xobserve(t, xopts(acct), n.server(t).URL); err != nil {
		t.Errorf("one minute ahead: %v", err)
	}
}

func TestXRPLHugeCloseTimeDoesNotReadAsFresh(t *testing.T) {
	acct := xAddr(1)
	for _, ct := range []string{"9223372036854775807", "9223372036854775806", "4611686018427387904", "99999999999999999999999999", "1e30", "-9223372036854775808", "-1", "0.5", `"abc"`, "null", "true"} {
		n := newXNode(acct)
		n.closeTime = ct
		obs, err := xobserve(t, xopts(acct), n.server(t).URL)
		if err == nil || obs != nil {
			t.Errorf("close_time %s was accepted: obs=%v", ct, obs)
			continue
		}
		if errors.Is(err, ErrStale) && strings.HasPrefix(ct, "9") {
			t.Errorf("close_time %s reads as stale, not as a bad value: %v", ct, err)
		}
	}
}

func TestXRPLNotValidatedLedger(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.notValidLed = true
	if _, err := xobserve(t, xopts(acct), n.server(t).URL); err == nil {
		t.Error("an unvalidated ledger must be an error")
	}
}

func TestXRPLAddressValidation(t *testing.T) {
	good := xAddr(7)
	if got, err := parseXRPLAddress(good); err != nil || got != good {
		t.Fatalf("%q: %v", got, err)
	}
	if got, err := parseXRPLAddress("  " + good + "\n"); err != nil || got != good {
		t.Fatalf("trimmed: %q %v", got, err)
	}
	// Flip one character in the middle: the checksum fails.
	mid := len(good) / 2
	flipped := good[:mid] + string(xAlphabet[(strings.IndexByte(xAlphabet, good[mid])+1)%58]) + good[mid+1:]
	// A payload with version 1 and a correct checksum is not a classic account address.
	p := make([]byte, 21)
	p[0] = 1
	// A payload of 20 bytes (short) with a correct checksum.
	short := xEncode(make([]byte, 20))
	long := xEncode(append([]byte{0}, make([]byte, 21)...))
	// An X-address-looking string: 47 characters starting with X.
	xaddr := "X" + strings.Repeat("7", 46)
	bad := map[string]string{
		"checksum":       flipped,
		"version":        xEncode(p),
		"short":          short,
		"long":           long,
		"x-address":      xaddr,
		"zero char":      good[:5] + "0" + good[6:],
		"capital O":      good[:5] + "O" + good[6:],
		"capital I":      good[:5] + "I" + good[6:],
		"lower l":        good[:5] + "l" + good[6:],
		"empty":          "",
		"spaces inside":  good[:5] + " " + good[5:],
		"hex address":    "0x1111111111111111111111111111111111111111",
		"prefix only":    "r",
		"lowercase body": strings.ToLower(good),
	}
	for name, v := range bad {
		got, err := parseXRPLAddress(v)
		if err == nil {
			t.Errorf("%s: accepted %q", name, got)
			continue
		}
		if v != "" && len(v) > 8 && strings.Contains(err.Error(), v) {
			t.Errorf("%s: the message echoes the value: %v", name, err)
		}
	}
	if _, err := parseXRPLAddress(xaddr); err == nil || !strings.Contains(err.Error(), "X-address") {
		t.Errorf("an X-address needs its own message: %v", err)
	}
	for _, v := range []any{nil, 123, true, []any{good}} {
		if _, err := parseXRPLAddress(v); err == nil {
			t.Errorf("%v accepted", v)
		}
	}
}

func writeXConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "adk-watch.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestXRPLConfig(t *testing.T) {
	good := xAddr(7)
	mk := func(opts string) string {
		return "targets:\n  - key: xrp\n    kind: xrpl-wallet\n    options:\n" + opts
	}
	cfg, err := LoadConfig(writeXConfig(t, mk("      address: \""+good+"\"\n      rpc_url_env: \"A,B\"\n      max_block_age: \"30m\"\n")))
	if err != nil || len(cfg.Targets) != 1 || cfg.Targets[0].Kind != kindXRPL {
		t.Fatalf("cfg=%v err=%v", cfg, err)
	}
	cases := map[string]string{
		"unknown option":   "      address: \"" + good + "\"\n      chain_id: 1\n",
		"typo":             "      address: \"" + good + "\"\n      rpc_url_envs: A\n",
		"evm option":       "      address: \"" + good + "\"\n      type: eoa\n",
		"bad address":      "      address: \"rNotValid\"\n",
		"missing address":  "      rpc_url_env: A\n",
		"number address":   "      address: 12345\n",
		"bad max age":      "      address: \"" + good + "\"\n      max_block_age: soon\n",
		"hex address":      "      address: \"0x1111111111111111111111111111111111111111\"\n",
		"x address":        "      address: \"X" + strings.Repeat("7", 46) + "\"\n",
		"negative max age": "      address: \"" + good + "\"\n      max_block_age: \"-5m\"\n",
	}
	for name, opts := range cases {
		if _, err := LoadConfig(writeXConfig(t, mk(opts))); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "rNotValid") {
			t.Errorf("%s: the bad address is echoed: %v", name, err)
		}
	}
}

func TestXRPLURLHygiene(t *testing.T) {
	const secret = "SECRETKEY123"
	acct := xAddr(1)
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>" + r.URL.Path + "</html>"))
	}))
	defer html.Close()
	s500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, r.URL.Path, 500)
	}))
	defer s500.Close()
	target := newXNode(acct)
	ts := target.server(t)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts.URL+"/"+secret, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"pad":"` + strings.Repeat("x", 2<<20) + `"}}`))
	}))
	defer big.Close()
	for name, u := range map[string]string{"html": html.URL, "500": s500.URL, "redirect": redir.URL, "dead": deadURL, "oversize": big.URL} {
		_, err := xobserve(t, xopts(acct), u+"/v2/"+secret+"?api_key="+secret)
		if err == nil {
			t.Errorf("%s: want an error", name)
			continue
		}
		msg := err.Error()
		host := strings.TrimPrefix(u, "http://")
		if strings.Contains(msg, secret) || strings.Contains(msg, host) || strings.Contains(msg, "127.0.0.1") {
			t.Errorf("%s: the error holds part of the address: %s", name, msg)
		}
		if !strings.Contains(msg, "RPC 1") {
			t.Errorf("%s: want the position: %s", name, msg)
		}
	}
	if m := target.methods(); len(m) != 0 {
		t.Errorf("a redirect was followed: %v", m)
	}
}

func TestXRPLEnvClient(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	n.regKey = xAddr(2)
	srv := n.server(t)
	t.Setenv("ADK_X_RPC_A", srv.URL+"/a")
	t.Setenv("ADK_X_RPC_B", srv.URL+"/b")
	o := newXRPLObserver(NewEnvClient, 0)
	o.now = fixedNow
	tg := Target{Key: "x", Kind: kindXRPL, Options: map[string]any{"address": acct, "rpc_url_env": "ADK_X_RPC_A, ADK_X_RPC_B"}}
	obs, err := o.Observe(context.Background(), tg)
	if err != nil || obs["regular_key"] != n.regKey {
		t.Fatalf("obs=%v err=%v", obs, err)
	}
	tg.Options["rpc_url_env"] = "https://node.example/SECRETKEY123"
	_, err = o.Observe(context.Background(), tg)
	if err == nil || strings.Contains(err.Error(), "SECRETKEY123") || strings.Contains(err.Error(), "node.example") {
		t.Errorf("err = %v", err)
	}
	tg.Options["rpc_url_env"] = "ADK_X_UNSET"
	if _, err = o.Observe(context.Background(), tg); err == nil {
		t.Error("unset variable")
	}
}

func TestXRPLSingleEndpointAndPlainHTTP(t *testing.T) {
	t.Setenv("ADK_X_A", "http://node-a.example/key")
	t.Setenv("ADK_X_B", "https://node-b.example/key")
	t.Setenv("ADK_X_C", "http://localhost:5005")
	one := Target{Kind: kindXRPL, Options: map[string]any{"rpc_url_env": "ADK_X_A"}}
	two := Target{Kind: kindXRPL, Options: map[string]any{"rpc_url_env": "ADK_X_A,ADK_X_B,ADK_X_C"}}
	if !SingleEndpoint(one) || SingleEndpoint(two) {
		t.Error("SingleEndpoint must apply to xrpl-wallet")
	}
	if got := PlainHTTPEndpoints(two); len(got) != 1 || got[0] != 1 {
		t.Errorf("PlainHTTPEndpoints = %v", got)
	}
}

func TestXRPLFindingsClassify(t *testing.T) {
	acct := xAddr(1)
	cfg := Config{Targets: []Target{{Key: "x", Kind: kindXRPL, Options: xopts(acct)}}}
	for _, f := range []string{"regular_key", "signer_list", "flags"} {
		o := Outcome{Changes: []Change{{Key: "x", Field: f, Old: "", New: "v"}}}
		got := Findings(o, cfg, nil)
		if len(got) != 1 || got[0].ID != "WA-002" || got[0].Severity != finding.Critical {
			t.Errorf("%s: %+v", f, got)
			continue
		}
		if !strings.Contains(got[0].Evidence, f+": (없음) -> v") {
			t.Errorf("%s: evidence = %q", f, got[0].Evidence)
		}
		if strings.Contains(got[0].Title, "소유자, 임계값") {
			t.Errorf("%s: the title speaks of EVM owners: %q", f, got[0].Title)
		}
	}
	o := Outcome{Changes: []Change{{Key: "x", Field: "address", Old: acct, New: xAddr(2)}}}
	if got := Findings(o, cfg, nil); len(got) != 1 || got[0].ID != "WA-007" {
		t.Errorf("address: %+v", got)
	}
}

func TestXRPLCompareFlow(t *testing.T) {
	acct := xAddr(1)
	n := newXNode(acct)
	srv := n.server(t)
	tg := Target{Key: "x", Kind: kindXRPL, Options: xopts(acct)}
	cfg := Config{Targets: []Target{tg}}
	o := xobserver(srv.URL)
	base, err := o.Observe(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	b := NewBaseline(fixedNow(), map[string]Observation{"x": base})
	n.setMu(func() { n.regKey = xAddr(2) })
	cur, err := o.Observe(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	out := Compare(b, map[string]Observation{"x": cur}, nil, cfg)
	if len(out.Changes) != 1 || out.Changes[0].Field != "regular_key" || out.Changes[0].Old != "" || out.Changes[0].New != xAddr(2) {
		t.Errorf("changes = %+v", out.Changes)
	}
}

// WA-002 is also what an XRPL change is reported as, so its texts must speak
// of the regular key, the signer list and the flags (the master key may be
// disabled by a flag), and must not claim to read the flag bits.
func TestXRPLTextsInWA002(t *testing.T) {
	e := readText(t, "../../explain/WA-002.md")
	f := readText(t, "../../fixes/WA-002/watch.md")
	for _, s := range []string{"regular_key", "signer_list", "flags", "마스터 키", "레귤러 키", "서명자 목록"} {
		if !strings.Contains(e, s) {
			t.Errorf("explain/WA-002.md lacks %q", s)
		}
	}
	for _, s := range []string{"regular_key", "signer_list", "flags"} {
		if !strings.Contains(f, s) {
			t.Errorf("fixes/WA-002/watch.md lacks %q", s)
		}
	}
	for _, s := range []string{"막는다", "안전", "방어한다"} {
		if strings.Contains(e+f, s) {
			t.Errorf("forbidden wording %q", s)
		}
	}
}
