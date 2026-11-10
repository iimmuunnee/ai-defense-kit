package autorun

import (
	"encoding/json"
	"strings"
	"testing"
)

// I-1(B1 재검토): 짧은 단어를 &&, |, --로 이은 흔한 명령은 단어가 11개를 넘어도 근거에
// 그대로 보인다. 명령은 글 규칙으로 보고, 공백으로 나눈 낱말마다 값 규칙을 더한다.
func TestRealCommandsAreShown(t *testing.T) {
	cmds := []string{
		"docker compose -f docker-compose.yml up --build --remove-orphans && npm run test -- --watch=false",
		"npx --yes prisma migrate deploy && npx prisma generate && npm run build && npm run start",
		`bash -c "npm ci && npm run lint && npm run test && npm run build && npm run start"`,
		"cd frontend && npm ci && npm run build && cd .. && go run ./cmd/server",
		"curl -fsSL https://get.pnpm.io/install.sh | sh - && pnpm install && pnpm run dev",
		`npx concurrently "npm run watch:css" "npm run watch:js" "npm run serve"`,
		"rm -rf node_modules dist && npm ci && npm run build -- --mode production",
		"bash -c 'echo setting up env && cp env.example env && npm ci && npm run db:seed && npm run dev'",
	}
	for _, cmd := range cmds {
		root := t.TempDir()
		q, _ := json.Marshal(cmd)
		write(t, root, ".vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"dev","type":"shell","command":`+string(q)+`,`+folderOpen+`}]}`)
		write(t, root, "package.json", `{"scripts":{"postinstall":`+string(q)+`}}`)
		fs := viaRunAll(t, root)
		if len(fs) < 2 {
			t.Fatalf("%q: findings = %d", cmd, len(fs))
		}
		// tasks.json의 근거는 JSON이라 따옴표가 \"로 나온다.
		inJSON := strings.ReplaceAll(cmd, `"`, `\"`)
		for _, f := range fs {
			if (!strings.Contains(f.Evidence, cmd) && !strings.Contains(f.Evidence, inJSON)) || strings.Contains(f.Evidence, "가림") {
				t.Errorf("%s %s: evidence %q lacks %q", f.ID, f.Location, f.Evidence, cmd)
			}
		}
	}
	if !strings.Contains(cmds[4], "https://get.pnpm.io/install.sh") {
		t.Fatal("test data")
	}
}

// 평범한 인자 배열은 항목을 이어 붙인 모양에서도 나열로 세지 않는다.
func TestRealArgsAreShown(t *testing.T) {
	for _, args := range [][]string{
		{"compose", "-f", "docker-compose.dev.yml", "up", "--build", "--remove-orphans", "--force-recreate", "--wait"},
		{"-c", "npm ci && npm run lint && npm run test && npm run build"},
		{"run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"},
		// 구분 문자로 끝나는 항목은 다음 항목과 붙여 본다(hideSplitShapes). 평범한 경로 목록은 그대로다.
		{"eslint", "--ext", ".js,.ts,.tsx", "src/", "tests/", "scripts/", "tools/", "--fix", "--cache"},
		{"-y", "@modelcontextprotocol/server-filesystem", "/home/dev/projects/", "/tmp/", "--read-only"},
		// 한 대시 플래그는 앞 항목에 붙여 보지만, 11개 이상 이어지지 않으면 나열이 아니다.
		{"-server", "-verbose", "-ea", "-Xmx2g", "-Dspring.profiles.active=dev", "-Dserver.port=8080", "-jar", "build/libs/app.jar", "--debug"},
		{"-y", "-i", "input.mp4", "-c:v", "libx264", "-preset", "fast", "-vf", "scale=1280:-1", "-c:a", "aac", "-b:a", "128k", "out.mp4"},
		{"test", "-v", "-race", "-count=1", "-run", "TestScan", "-timeout", "120s", "-cover", "-coverprofile", "cover.out", "-tags", "integration", "./..."},
		{"/srv", "/opt", "/data", "/mnt", "/home", "/etc", "/tmp"},
	} {
		root := t.TempDir()
		a := rawJSON(args)
		write(t, root, ".vscode/tasks.json", `{"tasks":[{"label":"run","type":"process","command":"docker","args":`+a+`,`+folderOpen+`}]}`)
		fs := viaRunAll(t, root)
		if len(fs) != 1 {
			t.Fatalf("%v: findings = %d", args, len(fs))
		}
		if !strings.Contains(fs[0].Evidence, `"args":`+a) || strings.Contains(fs[0].Evidence, "가림") {
			t.Errorf("%v: evidence %q", args, fs[0].Evidence)
		}
	}
}

// rawJSON is v as JSON without HTML escapes (& stays &), as the evidence shows it.
func rawJSON(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}
