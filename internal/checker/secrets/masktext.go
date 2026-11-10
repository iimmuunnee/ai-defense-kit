package secrets

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// maxMaskInput is the most text gitleaks is given. Its rules can take quadratic
// time on repeated text and cannot be cancelled, so this bounds the cost per call.
const maxMaskInput = 2048

// KeyBlockNotice replaces a private key block. A block is not looked into: what
// parses as a key can still run as commands, and real keys come in forms no parser
// here knows, so it is always hidden and always announced.
const KeyBlockNotice = "**** (개인 키처럼 보이는 블록을 가렸습니다. 이 안에 명령이 숨어 있을 수 있으니 파일을 직접 확인하세요)"

var (
	maskOnce     sync.Once
	maskDetector *detect.Detector // nil if gitleaks could not be set up

	// urlPassword matches the password in scheme://user:password@host.
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^\s/?#@:"'<>]*:)([^\s/?#@"'<>]+)(@)`)

	privateKeyBegin = regexp.MustCompile(`-----BEGIN ([A-Z0-9 -]*PRIVATE KEY(?: BLOCK)?)-----`)
)

// HasKeyBlock reports whether s holds a private key block that MaskTextCut hides.
func HasKeyBlock(s string) bool { return privateKeyBegin.MatchString(s) }

// MaskTextCut hides private key blocks in all of s, then returns the first maxMaskInput
// bytes of what is left, cut on a character boundary, with each secret gitleaks
// finds replaced by "****". cut reports that text was left out. It never treats
// gitleaks:allow as an exemption. It also hides the password of a URL such as
// scheme://user:password@host, which gitleaks may miss, unless that password
// holds shell text. A caller cuts to its display limit afterward.
func MaskTextCut(s string) (masked string, cut bool) {
	s = maskPrivateKeys(s)
	s, cut = maskInput(s)
	for _, secret := range gitleaksSecrets(s) {
		s = strings.ReplaceAll(s, secret, "****")
	}
	return urlPassword.ReplaceAllStringFunc(s, func(m string) string {
		p := urlPassword.FindStringSubmatch(m)
		if strings.ContainsAny(p[2], "$;|&()`\\") {
			return m
		}
		return p[1] + "****" + p[3]
	}), cut
}

// SecretsIn returns what MaskTextCut would hide through gitleaks in s, longest
// first. A caller uses it on text it built to give a value its name, then hides
// the results in the value itself.
func SecretsIn(s string) []string {
	s, _ = maskInput(s)
	return gitleaksSecrets(s)
}

// maskInput cuts s to maxMaskInput bytes on a character boundary.
func maskInput(s string) (string, bool) {
	if len(s) <= maxMaskInput {
		return s, false
	}
	n := maxMaskInput
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// gitleaksSecrets returns the maskable matches in s, longest first.
func gitleaksSecrets(s string) []string {
	if s == "" {
		return nil
	}
	maskOnce.Do(func() {
		d, err := newDefaultDetector()
		if err != nil {
			return
		}
		d.IgnoreGitleaksAllow = true
		maskDetector = d
	})
	if maskDetector == nil {
		return nil
	}
	var found []string
	for _, f := range maskDetector.DetectString(s) {
		if f.RuleID != "private-key" && maskable(f.Secret) {
			found = append(found, f.Secret)
		}
	}
	sort.Slice(found, func(i, j int) bool { return len(found[i]) > len(found[j]) })
	return found
}

// maskable decides whether a gitleaks match really is a secret. A real key is
// random and has a digit; a hyphenated word such as glpat-evil-package-name is a
// package name. Some rules also capture across shell text, which must stay
// visible, so a match holding whitespace, shell characters or a key header is
// left alone. Private key blocks are handled by maskPrivateKeys.
func maskable(secret string) bool {
	return strings.ContainsAny(secret, "0123456789") &&
		!strings.ContainsAny(secret, " \t\r\n\f\v;|&$`()<>'\"") &&
		!strings.Contains(secret, "-----BEGIN")
}

// maskPrivateKeys replaces each private key block with KeyBlockNotice, from its
// BEGIN through the END with the same label or, without one, to the end of s. It
// does not depend on line breaks, so literal \\n and collapsed text work alike.
func maskPrivateKeys(s string) string {
	var b strings.Builder
	for {
		m := privateKeyBegin.FindStringSubmatchIndex(s)
		if m == nil {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:m[0]])
		b.WriteString(KeyBlockNotice)
		end := "-----END " + s[m[2]:m[3]] + "-----"
		i := strings.Index(s[m[1]:], end)
		if i < 0 {
			return b.String()
		}
		s = s[m[1]+i+len(end):]
	}
}
