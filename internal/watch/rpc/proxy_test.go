package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDefaultTransportHasNoProxy(t *testing.T) {
	c := New([]string{"http://x"}, nil)
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("default transport = %#v, want a dedicated transport with no proxy", c.hc.Transport)
	}
	if tr := Transport(true); tr.Proxy == nil {
		t.Error("Transport(true) must use the environment proxy")
	}
	if tr := Transport(false); tr.Proxy != nil {
		t.Error("Transport(false) must not use a proxy")
	}
}

// The child process makes one call to rpc.invalid with HTTP_PROXY set. Its
// dialer is replaced, so nothing is resolved and nothing leaves this machine:
// the address it is asked to dial shows whether the proxy was used.
func TestProxyChildProcess(t *testing.T) {
	mode := os.Getenv("ADK_T_PROXY_CHILD")
	if mode == "" {
		t.Skip("helper for TestEnvProxyIsUsedOnlyWhenAllowed")
	}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer node.Close()

	c := New([]string{"http://rpc.invalid/v2/KEY"}, nil)
	base, ok := c.hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %#v", c.hc.Transport)
	}
	if mode == "allow" {
		base = Transport(true)
	}
	tr := base.Clone()
	var dialed []string
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		var d net.Dialer
		return d.DialContext(ctx, network, strings.TrimPrefix(node.URL, "http://"))
	}
	c.hc.Transport = tr
	if _, err := c.Call(context.Background(), "eth_chainId", nil); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\ndialed=%s\n", strings.Join(dialed, ","))
}

func TestEnvProxyIsUsedOnlyWhenAllowed(t *testing.T) {
	for mode, want := range map[string]string{"default": "dialed=rpc.invalid:80", "allow": "dialed=proxy.invalid:3128"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProxyChildProcess$", "-test.v")
		cmd.Env = append(os.Environ(), "ADK_T_PROXY_CHILD="+mode,
			"HTTP_PROXY=http://proxy.invalid:3128", "http_proxy=http://proxy.invalid:3128", "NO_PROXY=", "no_proxy=")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), want) {
			t.Errorf("%s: want %q, err=%v\n%s", mode, want, err, out)
		}
	}
}

func TestCallAllRawAcceptsObjects(t *testing.T) {
	srv := jsonServer(t, `{"timestamp":"0x10"}`)
	c := New([]string{srv.URL, srv.URL}, nil)
	res, err := c.CallAllRaw(context.Background(), "eth_getBlockByNumber", []any{"latest", false})
	if err != nil {
		t.Fatal(err)
	}
	var b struct{ Timestamp string }
	if len(res) != 2 || json.Unmarshal(res[1], &b) != nil || b.Timestamp != "0x10" {
		t.Errorf("res = %s", res)
	}
	if _, err := c.CallAll(context.Background(), "x", nil); err == nil {
		t.Error("CallAll must still accept only hex strings")
	}
}

func TestCallAllRawKeepsLimitsAndHidesURLs(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":"` + strings.Repeat("a", maxBody) + `"}`))
	}))
	defer big.Close()
	_, err := New([]string{big.URL + "/SECRETKEY"}, nil).CallAllRaw(context.Background(), "m", nil)
	if err == nil || !strings.Contains(err.Error(), "1MiB") || strings.Contains(err.Error(), "SECRETKEY") {
		t.Errorf("err = %v", err)
	}
	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL + "/SECRETKEY"
	down.Close()
	_, err = New([]string{url}, nil).CallAllRaw(context.Background(), "m", nil)
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("err = %v", err)
	}
	failed := NewFailed(fmt.Errorf("설정 오류"))
	if _, err := failed.CallAllRaw(context.Background(), "m", nil); err == nil {
		t.Error("a failed client must fail")
	}
}
