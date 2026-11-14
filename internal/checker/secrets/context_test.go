package secrets

import (
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func built(t *testing.T, rule, loc, match, secret string) finding.Finding {
	t.Helper()
	g := report.Finding{RuleID: rule, Secret: secret, Match: match, StartLine: 1, StartColumn: 1}
	return build(g, "secret-current", loc, finding.High, "코드에 비밀 키가 들어 있음", secret, "", "", "")
}

// 시험·문서·예제 자리의 키는 지우지 않고 "의심"으로 낮추며, 제목에 그 이유를 적는다.
// 등급은 그대로다(진짜 키가 시험 폴더에 있을 수도 있다).
func TestPlaceLowersConfidence(t *testing.T) {
	secret := randomSecret(t)
	for loc, why := range map[string]string{
		"tests/api.py":                  "시험",
		"pkg/server/handler_test.go":    "시험",
		"web/src/login.test.ts":         "시험",
		"web/src/login.spec.js":         "시험",
		"app/test_login.py":             "시험",
		"models/fixtures/user.yml":      "시험",
		"internal/x/testdata/conf.json": "시험",
		"src/__mocks__/client.js":       "시험",
		"docs/setup.md":                 "문서",
		"api-docs/source/compare.md":    "문서",
		"README.md":                     "문서",
		"guide/install.rst":             "문서",
		"examples/basic/main.go":        "예제",
		"samples/app.py":                "예제",
	} {
		f := built(t, "generic-api-key", loc, `api_key = "`+secret+`"`, secret)
		if f.Confidence != finding.Suspect || !strings.Contains(f.Title, why) || f.Severity != finding.High {
			t.Errorf("%s: confidence %s, severity %s, title %q (want suspect, high, %q)", loc, f.Confidence, f.Severity, f.Title, why)
		}
	}
	for _, loc := range []string{"app/config.py", "src/latest.ts", "contest/main.go", "attestation/key.go", "docsify.config.js"} {
		f := built(t, "generic-api-key", loc, `api_key = "`+secret+`"`, secret)
		if f.Confidence != finding.Certain || strings.Contains(f.Title, " - ") {
			t.Errorf("%s: confidence %s, title %q (want certain, no reason)", loc, f.Confidence, f.Title)
		}
	}
}

// generic-api-key가 키가 아닐 가능성이 큰 값을 잡으면 "의심"으로 낮추고 이유를 적는다.
func TestKeyNotLikelyLowersConfidence(t *testing.T) {
	// 값은 실행 중에 만든다. 저장소에 키 모양 문자열을 두지 않는다.
	v := randomSecret(t)
	argon := "$argon2id$v=19$m=65536,t=3,p=4$" + v[:8] + "$" + v[8:]
	bcrypt := "$2b$12$" + v + v[:13]
	uuid := strings.Join([]string{v[1:9], v[9:13], v[13:17], v[17:21], v[21:33]}, "-")
	for name, c := range map[string]struct{ match, secret, why string }{
		"hash name":     {`token_hash = "` + v + `"`, v, "해시"},
		"digest name":   {`sha256_digest: "` + v + `"`, v, "해시"},
		"password hash": {`passwd = "` + argon + `"`, argon, "해시"},
		"bcrypt":        {`password: "` + bcrypt + `"`, bcrypt, "해시"},
		"uuid":          {`api_key = "` + uuid + `"`, uuid, "UUID"},
	} {
		f := built(t, "generic-api-key", "app/config.py", c.match, c.secret)
		if f.Confidence != finding.Suspect || !strings.Contains(f.Title, c.why) {
			t.Errorf("%s: confidence %s, title %q (want suspect, %q)", name, f.Confidence, f.Title, c.why)
		}
	}
	// 형식이 정해진 규칙은 이름에 hash가 있어도 그대로다.
	secret := randomSecret(t)
	f := built(t, "github-pat", "app/config.py", `token_hash = "ghp_`+secret+`"`, "ghp_"+secret)
	if f.Confidence != finding.Certain {
		t.Errorf("github-pat: confidence %s", f.Confidence)
	}
}
