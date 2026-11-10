package rules

import (
	"strings"
	"testing"
)

func TestMaskEvidence(t *testing.T) {
	cases := map[string]string{
		`short = "abc"`:                    `short = "****"`,
		`k = abcdefghijklmnop1234`:         `k = abcd****`,
		`h = "Bearer abc def ghi jkl"`:     `h = "Bear****"`,
		`x = 'single quoted literal long'`: `x = 'sing****'`,
		`import portone`:                   `import portone`,
	}
	for in, want := range cases {
		if got := maskEvidence(in); got != want {
			t.Errorf("maskEvidence(%q) = %q, want %q", in, got, want)
		}
	}
}

// C1: assignment-shaped lines keep the name and mask the whole value, whatever its length.
func TestMaskEvidenceAssignmentShortValues(t *testing.T) {
	cases := map[string]string{
		`NEXT_PUBLIC_JWT_SECRET="mysecret123"`:       `NEXT_PUBLIC_JWT_SECRET="myse****"`,
		`NEXT_PUBLIC_JWT_SECRET=mysecret123`:         `NEXT_PUBLIC_JWT_SECRET=myse****`,
		`NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=xxxx`: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=****`,
		`export API_TOKEN=abc`:                       `export API_TOKEN=****`,
		`API_TOKEN = "hunter2"`:                      `API_TOKEN = "****"`,
		`api_token: hunter2`:                         `api_token: ****`,
		`api_token: 'hunter2'`:                       `api_token: '****'`,
		`"apiKey": "hunter2",`:                       `"apiKey": "****",`,
		`const KEY = 'hunter2';`:                     `const KEY = '****';`,
		`SECRET=hunter2 # 개발용`:                       `SECRET=**** (주석 생략)`,
		`DATABASE_URL=postgres://u:pw@db:5432/app`:   `DATABASE_URL=post****`,
		`EMPTY=`: `EMPTY=`,
	}
	for in, want := range cases {
		if got := maskEvidence(in); got != want {
			t.Errorf("maskEvidence(%q) = %q, want %q", in, got, want)
		}
	}
	for _, raw := range []string{"mysecret123", "hunter2"} {
		for in := range cases {
			if strings.Contains(in, raw) && strings.Contains(maskEvidence(in), raw) {
				t.Errorf("raw value %q leaked from %q", raw, in)
			}
		}
	}
}

// I2: identifiers and URL structure stay readable; only query values and opaque tokens are masked.
func TestMaskEvidenceKeepsIdentifiers(t *testing.T) {
	cases := map[string]string{
		`process.env.SUPABASE_SERVICE_ROLE_KEY!,`:      `process.env.SUPABASE_SERVICE_ROLE_KEY!,`,
		`const key = process.env.SUPABASE_SECRET_KEY;`: `const key = process.env.SUPABASE_SECRET_KEY;`,
		`if (NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY) {`: `if (NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY) {`,
		`get("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")`: `get("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY")`,
		"return `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirect}`;": "return `https://kauth.kakao.com/oauth/authorize?response_type=****&client_id=${clientId}&redirect_uri=${redirect}`;",
		`fetch("https://nid.naver.com/oauth2.0/authorize?client_id=abc123&state=xyz")`:                                        `fetch("https://nid.naver.com/oauth2.0/authorize?client_id=****&state=****")`,
		`@router.post("/webhook/portone")`:                                      `@router.post("/webhook/portone")`,
		`go("postgres://admin:pw1234@db.example.com/app")`:                      `go("postgres://****@db.example.com/app")`,
		`hook("https://hooks.example.com/services/T0001/Z8x2Kq9LmN3vB7cX1pR5")`: `hook("https://hooks.example.com/services/T0001/Z8x2****")`,
	}
	for in, want := range cases {
		if got := maskEvidence(in); got != want {
			t.Errorf("maskEvidence(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// Long opaque tokens and secret-looking literals are still masked, including
// tokens that resemble dotted chains (JWT) or upper-case runs without underscores.
func TestMaskEvidenceStillMasksOpaque(t *testing.T) {
	cases := map[string]string{
		`auth(eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2ln)`: `auth(eyJh****)`,
		`use(AKIAIOSFODNN7EXAMPLE)`:                       `use(AKIA****)`,
		`use("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")`: `use("wJal****")`,
		`run NEXT_PUBLIC_X=abc node`:                      `run NEXT_PUBLIC_X=**** node`,
	}
	for in, want := range cases {
		if got := maskEvidence(in); got != want {
			t.Errorf("maskEvidence(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// No raw value in evidence regardless of length or line shape,
// while the identifier that fired stays visible.
func TestMaskEvidenceNoShortValueLeaks(t *testing.T) {
	cases := []struct{ line, raw, keep string }{
		{`const NEXT_PUBLIC_JWT_SECRET: string = "abc123";`, "abc123", "const NEXT_PUBLIC_JWT_SECRET: string = "},
		{`const SUPABASE_SERVICE_ROLE_KEY: string = "abc123";`, "abc123", "SUPABASE_SERVICE_ROLE_KEY"},
		{`const portoneKey: string = "pk123";`, "pk123", "portoneKey"},
		{`const s = process.env.NEXT_PUBLIC_JWT_SECRET || "mysecret123";`, "mysecret123", "process.env.NEXT_PUBLIC_JWT_SECRET"},
		{`export const cfg = { NEXT_PUBLIC_JWT_SECRET: "hunter2", b: "y" };`, "hunter2", "NEXT_PUBLIC_JWT_SECRET"},
		{`export const cfg = { NEXT_PUBLIC_JWT_SECRET: "hunter2", b: "y" };`, `"y"`, "cfg"},
		{"const NEXT_PUBLIC_JWT_SECRET = `abc123`;", "abc123", "NEXT_PUBLIC_JWT_SECRET"},
		{`headers: { Authorization: "Bearer abc" } // NEXT_PUBLIC_X_SECRET`, "NEXT_PUBLIC_X_SECRET", "(주석 생략)"},
		{`headers: { Authorization: "Bearer abc" } // NEXT_PUBLIC_X_SECRET`, "abc", "Authorization"},
		{`key=abc; other=def`, "abc", "key="},
		{`key=abc; other=def`, "def", "other="},
		{`private readonly secret = "abc123"`, "abc123", "private readonly secret = "},
		{`static secret = "abc123"`, "abc123", "static secret = "},
		{`config["secret"] = "abc123"`, "abc123", `config["secret"] = `},
		{`portone.init({ apiSecret: "abc123" })`, "abc123", "portone.init({ apiSecret: "},
		{`SECRET: str = "abc123"`, "abc123", "SECRET: str = "},
		{`NEXT_PUBLIC_JWT_SECRET=my secret`, " secret", "NEXT_PUBLIC_JWT_SECRET="},
		{`fn("x", 'pw12')`, "pw12", "fn("},
		// Single-element arrays are values, not index keys.
		{`const NEXT_PUBLIC_JWT_SECRET = ["hunter2"];`, "hunter2", "NEXT_PUBLIC_JWT_SECRET"},
		{`app.keys = ['im a secret'];`, "secret", "app.keys = ['"},
		{`cookieSession({ keys: ['s3cr3t'] })`, "s3cr3t", "cookieSession({ keys: ['"},
		{`apiKeys: ['abc123'],`, "abc123", "apiKeys: "},
		{`jwt.sign(p, ["hunter2"][0])`, "hunter2", "jwt.sign(p, ["},
		{`KEY=abc#comment`, "abc", "KEY="},
		// # or // inside a word is part of the value.
		{`URL=https://x.com/cb#s3cr3tTok`, "s3cr3tTok", "URL="},
		{`url: https://x.com/cb#s3cr3tTok`, "s3cr3tTok", "url: "},
		{`DB_PASSWORD=Pa55#w0rdXYZ`, "w0rdXYZ", "DB_PASSWORD="},
		{`DB_PASSWORD=Pa55#w0rdXYZ`, "Pa55", "DB_PASSWORD="},
		{`export TOKEN=abc#def`, "def", "export TOKEN="},
		{`export TOKEN=abc#def`, "abc", "export TOKEN="},
		{`KEY=abc//def`, "abc", "KEY="},
		{`KEY=abc//def`, "def", "KEY="},
		{`fetch("https://x.com/cb#s3cr3tTok")`, "s3cr3tTok", `fetch("https://x.com/cb#`},
		{`go(https://x.com/cb#s3cr3tTok)`, "s3cr3tTok", "go(https://x.com/cb#"},
		{`obj["key"] = "abc123"`, "abc123", `obj["key"] = `},
	}
	for _, c := range cases {
		got := maskEvidence(c.line)
		if strings.Contains(got, c.raw) {
			t.Errorf("maskEvidence(%q) = %q leaks %q", c.line, got, c.raw)
		}
		if !strings.Contains(got, c.keep) {
			t.Errorf("maskEvidence(%q) = %q lost %q", c.line, got, c.keep)
		}
	}
	// Masked values shorter than 8 characters print no prefix at all.
	for in, want := range map[string]string{
		`NEXT_PUBLIC_JWT_SECRET="abc1234"`: `NEXT_PUBLIC_JWT_SECRET="****"`,
		`x = "abcdefgh"`:                   `x = "abcd****"`,
		`KEY=abc#comment`:                  `KEY=****`,
		`KEY=abc # note`:                   `KEY=**** (주석 생략)`,
		`fetch("https://x.com/cb#top")`:    `fetch("https://x.com/cb#****")`,
		`obj["key"]`:                       `obj["key"]`,
		`foo()["key"]`:                     `foo()["key"]`,
	} {
		if got := maskEvidence(in); got != want {
			t.Errorf("maskEvidence(%q) = %q, want %q", in, got, want)
		}
	}
	// addresses, routes and module names stay readable
	keep := []string{
		`@router.post("/webhook/portone")`,
		`import * as PortOne from "@portone/browser-sdk";`,
		`fetch("./api/login")`,
	}
	for _, l := range keep {
		if got := maskEvidence(l); got != l {
			t.Errorf("maskEvidence(%q) = %q, want unchanged", l, got)
		}
	}
}
