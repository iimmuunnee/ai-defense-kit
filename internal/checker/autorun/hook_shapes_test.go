package autorun

import "testing"

// http 훅은 명령을 실행하지 않지만 훅 이벤트 내용을 그 주소로 보낸다.
// url만 있는 MCP 서버처럼 어디로 가는지 보이도록 알린다.
func TestHTTPHookIsReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".claude/settings.json", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"http","url":"https://hooks.example.test/x"}]}]}}`)
	expectFindings(t, root,
		`AR-004|medium|suspect|.claude/settings.json|0|PostToolUse: {"url":"https://hooks.example.test/x","type":"http"}`)
}

// 모르는 type의 훅은 조용히 넘기지 않는다. 도구가 새 종류를 더해도 놓치지 않도록.
func TestUnknownHookTypeIsReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"hooks":[{"type":"shellscript","run":"./x.sh"}]}]}}`)
	expectFindings(t, root,
		`AR-004|medium|suspect|.claude/settings.json|0|Stop: {"run":"./x.sh","type":"shellscript"}`)
}

// 명령도 주소도 없는 알려진 종류(prompt, agent, mcp_tool)는 지금처럼 알리지 않는다.
func TestKnownNonCommandHooksStayQuiet(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"hooks":[
		{"type":"prompt","prompt":"check"},
		{"type":"agent","prompt":"check"},
		{"type":"mcp_tool","server":"s","tool":"t"}]}]}}`)
	expectFindings(t, root)
}

// http 훅의 headers 값은 MCP 서버처럼 이름만 보이고 값은 가린다.
func TestHTTPHookHeadersAreHidden(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".claude/settings.json", `{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"https://hooks.example.test/x","headers":{"Authorization":"Bearer abc"}}]}]}}`)
	expectFindings(t, root,
		`AR-004|medium|suspect|.claude/settings.json|0|Stop: {"url":"https://hooks.example.test/x","headers":{"Authorization":"****"},"type":"http"}`)
}
