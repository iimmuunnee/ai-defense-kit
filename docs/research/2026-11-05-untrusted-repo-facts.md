# 받은 저장소 점검의 근거와 숨김 경로 실험 기록

조회일: 2026-11-06 (모든 URL). 실험 환경: Windows 11, Go, osv-scanner v2.7.0, gitleaks v8.30.1, osv-scalibr (go.mod이 가리키는 버전).
이 문서는 `autorun` 점검기와 `--untrusted` 구현이 따를 사실만 적는다. 확인하지 못한 것은 "확인 필요"로 둔다.

읽은 방식 표기
- **원문**: `curl`로 받은 페이지의 본문(HTML 또는 공식 `.md` 원문)을 직접 읽었다.
- **요약 도구**: WebFetch(작은 모델이 페이지를 요약해 돌려주는 도구)로만 읽었다. 원문 확인 아님.

인용은 15단어 미만으로 한정했고, 나머지는 풀어 썼다.

---

## 1. 공식 문서에서 확인한 사실

### 1-1. VS Code 자동 작업 (`runOptions.runOn`)

URL: https://code.visualstudio.com/docs/debugtest/tasks (원문)

- `runOn` 값 중 `folderOpen`은 작업을 폴더가 열릴 때 실행하게 한다. 다른 값 `default`는 "Run Task" 명령으로 실행할 때만 돈다.
- 설정 `task.allowAutomaticTasks`가 `runOn: folderOpen` 작업의 자동 실행 허용 여부를 정한다. 값은 `off`(기본)와 `on` 두 가지다.
  - `off`: 자동 작업을 실행하지 않는다. 해당 작업공간에서 아직 고르지 않았다면 한 번 허용/거부를 묻는다. 거부하면 다시 묻지 않는다.
  - `on`: 신뢰하는 작업공간에서 묻지 않고 항상 실행한다.
- 원문에 그대로 있는 문장(인용): "Automatic tasks never run in an untrusted workspace" (설정값과 무관하다는 뜻으로 이어진다).
- `Tasks: Manage Automatic Tasks` 명령으로 허용/거부를 바꿀 수 있다.
- 따라서 문서상 위험이 생기는 시점은 (1) 작업공간을 신뢰하고 (2) 자동 작업을 허용하거나 `on`으로 둔 경우다. 신뢰하지 않은 폴더(제한 모드)에서는 실행되지 않는다고 적혀 있다.

### 1-1b. `runOn`의 값 `worktreeCreated`와 대소문자

URL: https://github.com/microsoft/vscode (소스 `src/vs/workbench/contrib/tasks/common/tasks.ts`, `taskConfiguration.ts`, 2026-11-06에 `raw.githubusercontent.com`의 main 브랜치 원문을 `curl`로 읽음)

- `RunOnOptions` 열거형이 `default`, `folderOpen`, `worktreeCreated` 세 값을 가진다. `worktreeCreated`는 위 1-1의 공식 문서 페이지(`tasks` 문서 HTML과 `vscode-docs`의 `tasks.md`)에는 나오지 않는다(두 곳 모두 grep 0건). 소스에서만 확인한 값이며, 무엇을 계기로 실행되는지는 확인하지 못했다(확인 필요).
- 설정 값을 읽는 코드가 `value.toLowerCase()`로 비교한다(`folderopen`, `worktreecreated`). 그래서 `"FOLDEROPEN"`도 `folderOpen`으로 읽힌다.
- 구현 결정: `runOn`이 `default`(대소문자 무시)가 아닌 문자열이면 모두 `AR-001`로 알린다. 모르는 값이어도 알리는 쪽이 놓치는 쪽보다 낫기 때문이다.

### 1-2. VS Code 작업공간 신뢰 (Restricted Mode)

URL: https://code.visualstudio.com/docs/editing/workspaces/workspace-trust (원문)

- 처음 여는 낯선 폴더는 제한 모드로 열리고, 목적은 "자동 코드 실행"을 막는 것이라고 설명한다. 사용자가 "신뢰하지 않음"을 골라도 제한 모드가 된다.
- 제한 모드가 막거나 제한하는 기능으로 AI 에이전트, 터미널, 작업(tasks), 디버깅, 작업공간 설정, 확장을 든다.
- 작업은 `.vscode` 폴더에 정의되어 저장소 소스에 포함되므로, 악의적 작업이 있으면 복제한 누구에게든 실행될 수 있다고 적혀 있다. 제한 모드에서 작업을 실행하거나 목록만 열어도 신뢰 여부를 묻는다.
- Codespaces 연결이나 실행 중인 Docker 컨테이너에 붙는 경우 자동으로 신뢰한다고 적혀 있다. 관리되는 환경이라는 이유다.
- 이 페이지에 `task.allowAutomaticTasks`나 `runOn`의 상호작용은 나오지 않는다. 그 부분은 1-1 페이지에 있다.

### 1-3. `*.code-workspace` 파일의 `tasks`

URL: https://code.visualstudio.com/docs/editing/workspaces/multi-root-workspaces , https://code.visualstudio.com/docs/editing/workspaces/workspaces (원문)

- 작업공간 파일의 `"tasks"` 항목에 작업공간 범위 작업을 둘 수 있고, `shell`과 `process` 유형만 허용된다고 적혀 있다.
- 두 페이지와 tasks 페이지 어디에도 `runOn`/`folderOpen`이 작업공간 파일의 작업에서도 동작한다는 설명은 없다. grep으로 세 페이지에서 `runOn`, `folderOpen`을 찾았으나 `tasks` 페이지 외에는 나오지 않았다.
- 결론: **작업공간 파일의 `tasks`에서 `folderOpen` 자동 실행이 되는지는 공식 문서로 확인하지 못했다. 확인 필요.** 확인되지 않았으므로 `AR-001`에 넣지 않고 후속 과제로 남긴다는 전제로 구현한다.
- 참고: 사용자가 `.code-workspace`를 직접 열어야 하는 흐름이라, 폴더만 열 때와 시나리오가 다르다(문서에서 확인한 사실은 아니고 구조상의 관찰).

### 1-4. Microsoft 두 글이 `tasks.json`에 대해 말한 것

두 글 모두 `curl`로 직접 받으려 했으나 403/502로 막혀 **본문 원문을 읽지 못했다. 아래는 요약 도구로만 읽은 내용이다.** 정확한 문구는 확인 필요.

- 2026-03-11 글 (Contagious Interview): https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/
  - 요약 도구 결과: VS Code 경로에서는 내려받은 패키지를 열고 저장소 작성자를 신뢰하라는 확인에 동의하면, VS Code가 저장소의 "작업 설정 파일"을 자동 실행하고 거기서 백도어를 받아 온다. 샘플 작업은 URL 단축 서비스에서 vercel.app 주소로 넘어갔다.
  - 요약 도구 결과: 이 글은 `tasks.json`, `.vscode`, `runOn`, `folderOpen`을 이름으로 말하지 않는다("task configuration file"이라고만 한다). 즉 이 글은 "신뢰하면 작업 설정이 실행된다"는 사실까지만 뒷받침한다.
  - 요약 도구 결과: 훔치는 대상으로 API 토큰, 클라우드 자격 증명, 서명 키, 암호화폐 지갑 관련 정보, 비밀번호 관리자 자료, 환경 설정 파일, 소스 코드를 든다. npm 경로(GitHub 등에 있는 npm 패키지를 받아 실행)와 붙여넣기 명령 경로도 있다고 한다.
- 2026-02-24 글 (C2 developer targeting): https://www.microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign/
  - 요약 도구 결과: 일부 저장소는 `.vscode/tasks.json`에 폴더가 열릴 때(`folderOpen`) 실행되는 작업을 두고, 저장소가 "Next.js 프로젝트로 위장"했다. 실행은 개발자가 프로젝트를 "열고 신뢰"하는 순간 시작된다고 한다. Vercel에서 JavaScript 로더를 받아 Node.js로 실행하는 연쇄다.
  - 요약 도구 결과: 일부 변종은 작업 실행이 막힌 경우를 대비해 난독화한 JavaScript로 작업공간 초기화 시 실행되는 대비책을 둔다. `jquery.min.js` 같은 파일에 난독화 코드를 심은 경우도 있다고 한다.
  - 요약 도구 결과: 방어 권고로 작업공간 신뢰와 제한 모드를 알 수 없는 출처의 저장소에 기본으로 쓰고, 신뢰하기 전에 작업공간 자동화 파일을 검토하라고 한다.
  - 요약 도구 결과: `runOptions`라는 단어는 글에 없고 `runOn`/`folderOpen`은 있다고 한다(JSON 구조는 `runOptions.runOn`이므로 글의 표기는 줄여 쓴 것으로 보인다. 원문 미확인).
  - 요약 도구 결과: `.code-workspace`, devcontainer, `package.json` scripts는 이 글에 나오지 않는다.

### 1-5. Dev Containers

URL: https://containers.dev/implementors/json_reference/ (원문)

- `initializeCommand`: 호스트 머신에서 컨테이너 초기화 중 실행된다. 컨테이너 생성 때와 이후 시작 때도 실행되며 한 세션에 여러 번 돌 수 있다. 소스 코드가 있는 곳에서 실행하며, 클라우드 서비스라면 그 클라우드다.
- `onCreateCommand`, `updateContentCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand`: 컨테이너 안에서 실행된다. 앞 세 개는 컨테이너가 만들어질 때 차례로, 뒤 둘은 시작과 연결 시점이다. 하나가 실패하면 뒤 스크립트는 실행되지 않는다.
- 명령은 문자열, 배열, 객체 형식을 쓴다(객체는 항목을 병렬 실행). 문서에 세 형식 비교 예제가 있다.
- 이 참조 문서에 `승인`, `신뢰`, `prompt`에 해당하는 설명은 **없다**(grep으로 `approv`, `trust`, `prompt`를 찾았으나 관련 문장 없음). 승인 절차가 있다고 쓰면 안 된다.

### 1-6. npm

URL: https://docs.npmjs.com/cli/v11/using-npm/scripts , https://docs.npmjs.com/cli/v11/commands/npm-install (원문)

- 생명주기 표에서 `npm install`과 `npm ci`는 `preinstall`, `install`, `postinstall`, `prepublish`, `preprepare`, `prepare`, `postprepare`를 차례로 실행한다고 나온다(원문(표 변환): HTML 표를 텍스트로 변환해 읽었다). `prepublish`는 폐기 예정이며 `npm publish`에서는 돌지 않지만 `npm ci`와 `npm install`에서는 돈다고 적혀 있다. `prepare`는 인자 없는 로컬 `npm install`에서 돈다(특정 패키지를 지정한 설치에서는 돌지 않는다).
- `--ignore-scripts`(기본 false): 참이면 `package.json`의 스크립트를 실행하지 않는다. 다만 `npm start`, `npm test`, `npm run` 같은 명시적 실행 명령은 그 스크립트를 실행하되 pre/post는 돌지 않는다.
- v11 문서에 의존성 설치 스크립트용 정책이 새로 있다: `allow-scripts`, `strict-allow-scripts`, `dangerously-allow-all-scripts`. `--ignore-scripts`가 이들보다 우선한다. 기본값에서 검토되지 않은 의존성 스크립트는 경고와 함께 실행된다고 적혀 있다.
- 따라서 "내용을 확인하기 전에는 설치하지 마세요. 꼭 해야 하면 `--ignore-scripts`를 붙이세요"는 공식 문서로 뒷받침된다. 단 내 npm 버전이 v11이 아니면 정책 옵션은 적용되지 않을 수 있다(확인 필요).

### 1-7. Claude Code

모두 `https://code.claude.com/docs/en/<이름>.md` 원문을 `curl`로 직접 읽었다. 요약 도구 결과는 쓰지 않았다.

**신뢰 규칙 ("What runs before you trust a folder")**: https://code.claude.com/docs/en/permissions.md

- 신뢰 대화상자는 대화형 세션에서만 나온다. `claude -p`나 SDK 세션은 절대 보여 주지 않는다.
- 해당 절의 표(저장소가 제공하는 내용 / 부모 폴더만 신뢰한 경우 / `-p`·SDK에서 신뢰하지 않은 폴더):
  - 설정 파일의 hooks, `env` 블록, `apiKeyHelper` 같은 도우미 명령, 프로젝트 스킬의 hooks: 두 경우 모두 **사용됨(Used)**.
  - `permissions.allow`와 `additionalDirectories`: 신뢰하기 전엔 쓰지 않음.
  - 하위 에이전트 frontmatter hooks, `@skills-dir` 플러그인, `extraKnownMarketplaces`: 사용되지 않음.
  - `.mcp.json` 서버: 부모 폴더만 신뢰한 경우 연결 전에 묻는다(저장소가 자기 설정으로 한 승인은 인정 안 됨). `-p`·SDK에서는 **묻지 않고 연결**한다.
  - `.mcp.json` 서버의 `headersHelper`: 신뢰 대화상자를 거치기 전에는 실행하지 않는다.
- 같은 문서의 권고: 낯선 저장소에서 `claude -p`를 돌리기 전에 `--setting-sources user`, `--bare`, `--settings '{"disableAllHooks": true}'`, `disabledMcpjsonServers` 중 하나를 쓰라고 한다.

**settings 훅**: https://code.claude.com/docs/en/hooks.md ("Workspace trust" 절)

- 대화형 세션: 모든 설정 파일(자기 `~/.claude/settings.json` 포함)의 hooks를 작업 폴더 신뢰 대화상자를 수락할 때까지 보류한다.
- `-p`·SDK 세션: 대화상자를 보여 주지 않고 폴더를 신뢰한 것으로 취급하므로, 한 번도 신뢰하지 않은 폴더의 `.claude/settings.json` hooks가 **실행된다**.

**`.mcp.json` 승인**: https://code.claude.com/docs/en/mcp.md

- 대화형: 프로젝트 범위 서버는 쓰기 전에 승인을 묻는다. `claude -p`, Agent SDK 등 프롬프트를 못 띄우는 곳에서는 묻지 않고 프로젝트 서버를 로드한다.
- 저장소가 커밋해 둔 `enableAllProjectMcpServers`/`enabledMcpjsonServers` 승인은 신뢰하지 않은 폴더에서 무시된다. 복제한 저장소가 자기 서버를 스스로 승인할 수 없다.
- `headersHelper`는 임의의 셸 명령으로 실행되고, `.mcp.json`의 것은 폴더 신뢰 대화상자 수락 후에만 실행된다.

**보안 개요**: https://code.claude.com/docs/en/security.md (원문)

- 대화형 세션은 신뢰하지 않은 폴더에서 신뢰 대화상자를 보여 주고, `.mcp.json` 서버는 별도 승인 프롬프트가 있으며, `-p` 세션은 둘 다 보여 주지 않는다고 적혀 있다.

**settings의 도우미 명령과 `settings.local.json`**: https://code.claude.com/docs/en/settings-reference.md , https://code.claude.com/docs/en/statusline.md , https://code.claude.com/docs/en/settings.md (원문, 조회일 2026-11-06)

- 참조 표가 자기 명령을 실행하는 설정으로 `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `fileSuggestion`, `gcpAuthRefresh`, `otelHeadersHelper`, `statusLine`, `subagentStatusLine`을 들고, 범위를 모두 "Any file"로 적는다. `policyHelper`(관리 설정 전용), `sshHostCommands`(사용자 또는 관리 설정)는 저장소 파일에서 쓰이지 않으므로 뺐다.
- permissions.md: 설정 파일의 hooks, `env` 블록, `apiKeyHelper` 같은 도우미는 부모 폴더만 신뢰했을 때와 `-p`·SDK에서 모두 "Used"다. `--bare`에서도 `awsAuthRefresh` 같은 도우미와 `env`는 적용되고 `apiKeyHelper`는 `--settings`에서만 읽는다고 적혀 있다.
- statusline.md: 신뢰를 수락하기 전까지 상태 줄은 비어 있고, `statusLine`은 설정 파일 훅과 같은 신뢰 규칙으로 돈다고 적혀 있다. `-p`에는 상태 줄 화면이 없어 실제로 도는지는 확인하지 못했다. **자동 실행 여부 확인 필요.** `subagentStatusLine`도 같은 규칙이라고 적혀 있다.
- 각 도우미가 실행되는 시점은 도우미마다 다르다(`otelHeadersHelper`는 시작 때와 주기적으로, `awsAuthRefresh`는 자격 증명 확인이 실패할 때). `fileSuggestion`, `gcpAuthRefresh`, `awsCredentialExport`의 시점은 하나씩 시험하지 않았다. **자동 실행 여부 확인 필요.**
- settings.md: `.claude/settings.local.json`은 프로젝트 개인 설정이고 프로젝트 공유 설정보다 우선한다. 저장소에 커밋되어 받은 파일이 `-p`에서 그대로 쓰이는지는 문서에 명시되어 있지 않다. **자동 실행 여부 확인 필요.**
- mcp.md: `headersHelper`는 임의의 셸 명령이다. `.mcp.json`과 로컬 범위 서버의 것은 그 폴더의 신뢰 대화상자를 수락한 뒤에만 돌고, `-p`·SDK도 수락 전에는 돌리지 않는다(v2.1.238 이전에는 `-p`에서 확인 없이 돌았다고 적혀 있다). 그 전에는 고정된 `headers`만으로 연결한다.
- hooks.md: 훅 유형에 `command` 외에 `http`, `mcp_tool`, `prompt`, `agent`가 있다. `AR-004`는 `command`만 알린다. 나머지는 README 한계에 적었다.

### 1-7b. VS Code MCP 설정

URL: https://code.visualstudio.com/docs/agents/run/manage-mcp-servers.md , https://code.visualstudio.com/docs/agents/reference/mcp-configuration.md , https://code.visualstudio.com/docs/agent-customization/mcp-servers.md (원문, 조회일 2026-11-06)

- `.vscode/mcp.json`과 `.mcp.json` 서버는 작업공간 신뢰를 따른다. 제한 모드에서는 시작되지 않고, 신뢰한 작업공간에서는 MCP 신뢰를 따로 묻지 않고 시작될 수 있다.
- `chat.mcp.autostart`(실험 기능)의 기본값 `newAndOutdated`는 채팅 메시지를 보낼 때 한 번도 돌지 않았거나 설정이 바뀐 서버를 시작한다. 이 값을 `never`로 둬도 Copilot 쪽이 자기 서버를 따로 시작하는 것은 막지 못한다고 적혀 있다. 폴더를 여는 것만으로 시작되는지는 문서에서 찾지 못했다. **자동 실행 여부 확인 필요.**
- VS Code 형식의 최상위 키는 `servers`, 이식 가능한 Copilot 형식은 `mcpServers`다. 문서는 `.vscode/mcp.json`을 호환용으로 남아 있다고 적고, 안내 화면에는 폐기 예정으로 표시된다고 적는다. 서버는 `command`(stdio) 또는 `url`(http)을 쓴다.
- 구현 결정: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` 모두 두 키를 읽는다. 다른 파일의 `servers`는 쓰이지 않을 수 있지만 알리는 쪽이 놓치는 쪽보다 낫다.

### 1-8. Cursor

URL: https://cursor.com/docs/context/mcp , https://cursor.com/docs/agent/security , https://cursor.com/docs/cli/reference/parameters (원문)

- 프로젝트 설정은 `.cursor/mcp.json`이다. 서버를 시작하는 시점(폴더를 열 때인지, 사용할 때인지)에 대한 설명은 MCP 페이지에서 **찾지 못했다. 확인 필요.**
- 보안 페이지: "모든 MCP 연결은 사용자 승인이 필요하다"고 적혀 있고, 승인한 뒤에도 도구 호출마다 승인이 필요하다. 작업공간 신뢰는 기본적으로 꺼져 있다고 적혀 있다.
- CLI 참조: `--approve-mcps`는 모든 MCP 서버를 자동 승인하고, `--trust`는 헤드리스에서 작업공간을 묻지 않고 신뢰한다. `agent mcp enable <식별자>`는 서버를 로컬 승인 목록에 추가한다.
- 위 승인이 "서버 시작 전"의 승인인지 "도구 호출 전"의 승인인지는 공식 문서만으로 구분되지 않는다. 포럼 글은 프로젝트 MCP 승인이 있다고 하지만 비공식이므로 근거로 쓰지 않는다.
- 결론: 시작 시점은 확인 필요. 파일이 있으면 명령을 보여 주기만 한다(구현의 가정인 "명령만 보여 준다"와 같다).

### 1-9. OpenSSF

URL: https://openssf.org/?p=11003 (요약 도구)

- 요약 도구 결과: 제목 "Detecting Malicious Packages using the OSV API", 작성자 Cloudsmith 소속, 2026-05-20 갱신. 악성 패키지 기록의 ID는 `MAL-`로 시작하며 api.osv.dev로 이름과 버전을 조회할 수 있고, osv-scanner를 CI에서 쓸 수 있다고 한다. 원문 미확인.

---

## 2. 숨김 경로 실험

### 2-1. 방법

- `osvscanner.DoScan`을 직접 부르는 임시 프로그램을 만들었다. 설정은 adk의 `deps` 점검기와 같다: `DirectoryPaths`=점검 폴더, `Recursive`=true, 전이 의존성 스캔 끔, `filesystem/vendored` 플러그인 끔. 옵션으로 `ConfigOverridePath`, `CompareOffline`, `LocalDBPath`를 줄 수 있다. 출력은 패키지별 취약점 ID, 별칭, 그룹이다.
- 현재 `adk`는 이 저장소의 `cmd/adk`를 빌드해 `adk scan <폴더> --format md,json`으로 돌렸다.
- 실험 코드와 픽스처는 임시 폴더 아래에만 있고 커밋하지 않았다.
- 잠금 파일(`package-lock.json`, lockfileVersion 3)에는 `lodash@4.17.15`(알려진 취약점 5건)와 `op-vscode@1.0.0`(MAL 항목)을 이름·버전만 적었다. `package.json`은 이름·버전만 있는 빈 껍데기다. 어떤 패키지도 설치하거나 내려받지 않았다.
- 외부 조회는 OSV API(`api.osv.dev`)가 받는 이름·버전·생태계뿐이다.

### 2-2. osv-scanner 설정 파일 결과

기준(설정 없음): 취약점 5건(lodash) + `MAL-2025-342` 1건(op-vscode), `ERR=vulnerabilities found`.

| 실험 | 설정 위치 | 결과 |
|---|---|---|
| E1 | 잠금 파일과 같은 폴더의 `osv-scanner.toml`에 `[[IgnoredVulns]]`로 lodash 5건과 `MAL-2025-342`를 적음 | **전부 사라짐**. `DoScan`이 오류 없이(`ERR=<nil>`) 빈 결과를 돌려줌. 사라진 항목은 INFO 로그로만 남음("filtered out because …", "Filtered 6 vulnerabilities") |
| E1 + adk | 같은 픽스처를 현재 adk로 점검 | 리포트 `findings` 0건. 경고에는 secrets의 "git 기록이 없다"만 있고 숨겨졌다는 표시 없음 |
| E2 | `.osv-scanner.toml`(앞에 점)에 같은 내용 | **숨기지 못함**. 6건 모두 나옴. v2.7.0은 설정 파일 이름을 `osv-scanner.toml`로만 찾음(소스 `OSVScannerConfigName`로도 확인) |
| E3 | E1 폴더에 `ConfigOverridePath`=점검 폴더 밖 **임시 폴더**에 만든 **빈 파일** | **되살아남**. 6건 모두 나옴 |
| E4a | 설정이 점검 루트에 있고 잠금 파일은 `sub/`에 있음 | 숨기지 못함. 설정은 **잠금 파일이 있는 폴더**에서만 찾음 |
| E4b | 설정이 잠금 파일이 있는 하위 폴더 `sub/`에 있음 | **숨김**(깊이와 상관없이 가능). 빈 `ConfigOverridePath`를 주면 되살아남(하위 폴더 설정도 무시됨) |
| E5 | `[[PackageOverrides]]`에 `name="op-vscode", ignore=true`, `name="lodash", vulnerability.ignore=true` | **전부 사라짐**(패키지 자체 제외 + 취약점 무시). `ERR=<nil>`. 빈 `ConfigOverridePath`를 주면 되살아남 |
| E6 | `ConfigOverridePath`가 존재하지 않는 파일 | `DoScan`이 오류를 돌려주고 `ERROR` 로그("Failed to read config file …")도 남김 |
| E7 | `ConfigOverridePath`가 TOML이 아닌 파일 | 마찬가지로 오류 반환 + `ERROR` 로그 |

관찰
- `IgnoredVulns`는 ID나 별칭이 맞으면 `MAL-` 항목도 가린다. 가리는 범위는 `[[IgnoredVulns]]`만이 아니라 `[[PackageOverrides]]`(패키지 통째 제외)도 포함한다. `AR-006`이 `osv-scanner.toml`의 존재를 알리는 데서 그치면 충분하지만, "설정이 있으면 결과를 숨길 수 있다"는 문구는 `IgnoredVulns`뿐 아니라 패키지 제외도 포함해야 한다.
- 설정 파일은 어느 깊이에서든 잠금 파일 옆에 있으면 효력이 있다. `AR-006`은 루트만이 아니라 어느 깊이의 `osv-scanner.toml`도 찾아야 한다.
- 빈 `ConfigOverridePath`는 위 모든 경우를 한 번에 무력화한다. 실험은 파일 시스템의 빈 임시 파일(저장소 밖)로 했다.
- adk의 `quietScan`은 `ERROR` 수준 로그를 실패로 올린다. 존재하지 않거나 해석 못 하는 override 파일은 `ERROR` 로그와 오류 반환이라 실패로 처리되고, 숨겨진 결과는 INFO뿐이라 adk의 현재 코드는 숨김을 알아채지 못한다.

**소스에서 읽은 것과 시험 결과 추가** (아래 첫 항목은 소스를 읽은 것이고 시험하지 않았다)
- (소스 확인, 시험하지 않음) `ConfigOverridePath`를 주면 `Manager.Get`이 override 설정을 먼저 돌려주고 끝나므로, osv-scanner는 저장소 자신의 `osv-scanner.toml`을 읽지 않는다(`internal/config/manager.go`의 `Get` 앞부분).
- (시험함) 잠금 파일 옆에 TOML이 아닌 `osv-scanner.toml`을 두고 override 없이 돌리면, `DoScan`은 `ERROR` 로그("Ignored invalid config file …", `manager.go` 61행)를 남기고 결과는 그대로 6건을 돌려준다. 현재 adk는 이 `ERROR` 로그를 `deps` 실패로 올려 리포트에 `deps (실패)` 경고를 내고 `findings`는 0건이다. 즉 `--untrusted` 없이 깨진 저장소 설정은 결과를 **숨기지 않고** `deps`를 실패시킨다.
- (시험함) 같은 깨진 설정 폴더에 점검 폴더 밖의 빈 `ConfigOverridePath`를 주면 `ERROR` 로그 없이 6건이 모두 나온다. 깨진 저장소 설정도 override로 함께 무력화된다.

### 2-3. gitleaks 숨김 경로

픽스처: 가짜 GitHub 토큰 형식(`ghp_` + 무작위 36자, 실제 키가 아님)을 `config.js`에 둔 임시 git 저장소. 현재 파일 점검과 git 기록 점검을 따로 보려고 두 계열을 만들었다. (a) 현재 파일에 키가 있는 저장소, (b) 키를 첫 커밋에 넣고 두 번째 커밋에서 지운 "기록에만 있는" 저장소. `.gitleaksignore`에는 gitleaks가 계산하는 지문(파일: `경로:규칙:줄`, 기록: `커밋:경로:규칙:줄`)을 임시 프로그램으로 구해 정확히 적었다.

| 실험 | 현재 파일 점검 | git 기록 점검 |
|---|---|---|
| 기준(설정 없음) | 탐지됨 | 탐지됨 |
| `.gitleaksignore`에 정확한 지문 | **숨기지 못함**(탐지됨) | **숨기지 못함**(탐지됨) |
| `.gitleaks.toml`에 `[allowlist] paths` | **숨기지 못함** | **숨기지 못함** |
| 줄 끝 `// gitleaks:allow` | **숨김** | **숨김** (그 줄이 커밋에 처음부터 `allow`와 함께 들어간 경우. 허용 표시가 두 번째 커밋에서 추가되면 첫 커밋 기록은 여전히 탐지됨) |

- 소스 확인: gitleaks 라이브러리에서 `.gitleaksignore`는 `Detector.AddGitleaksIgnore`로만 읽히고 이 함수는 gitleaks CLI 쪽(`cmd`)에서만 부른다. adk는 `NewDetectorDefaultConfig`를 쓰므로 `.gitleaksignore`도 `.gitleaks.toml`도 읽지 않는다. 실험 결과와 일치한다.
- `gitleaks:allow`는 라이브러리 `detect.go`가 처리하며 `Detector.IgnoreGitleaksAllow` 공개 필드(v8.30.1)가 있다. 이 필드를 true로 하자 `gitleaks:allow` 줄에서도 탐지가 **복원**됐다(현재 파일, 기록 모두; 임시 프로그램에서 확인).
- adk 쪽 현재 동작: 위 `gitleaks:allow` 픽스처를 adk로 점검하면 `findings` 0건이다. 숨겨졌다는 경고는 없다.

---

## 3. `MAL-` 실험

### 3-1. 대상

- `https://osv.dev/vulnerability/MAL-2025-342` 페이지는 자바스크립트로 그려져 `curl`로는 내용을 얻을 수 없어, 같은 데이터를 주는 OSV API(`https://api.osv.dev/v1/vulns/MAL-2025-342`)로 읽었다. 페이지 자체는 HTTP 200.
- 항목: ID `MAL-2025-342`, 요약 "Malicious code in op-vscode (npm)", 게시 2025-01-22, 수정 2025-03-31. 별칭 `GHSA-mh79-jr8w-w349`, `SNYK-JS-OPVSCODE-8660173`.
- 영향: 패키지 `op-vscode`(npm), 영향 버전 `1.0.0`, `1.1.0`(범위는 `introduced: 0`). 심각도(`severity`) 필드는 없다.
- 세부 설명에는 이 패키지가 설치된 컴퓨터는 완전히 침해된 것으로 보고, 비밀과 키를 다른 컴퓨터에서 즉시 교체하고, 패키지는 제거하라는 안내가 있다. 제거해도 안전을 보장하지 못한다는 문장도 있다.
- 잠금 파일에 `op-vscode@1.0.0`을 이름·버전만 적어 조회했다. 패키지를 설치하거나 내려받지 않았다.

### 3-2. 온라인 `DoScan` 결과

- `MAL-2025-342`가 **나온다**. 취약점 ID는 `MAL-2025-342`, 별칭은 `GHSA-mh79-jr8w-w349`, `SNYK-JS-OPVSCODE-8660173`.
- 그룹: `ids=[MAL-2025-342]`, `aliases=[GHSA-mh79-jr8w-w349, MAL-2025-342, SNYK-JS-OPVSCODE-8660173]`. 즉 GHSA 별칭은 그룹의 별칭이고 별도 항목이 아니다. 최대 점수(`MaxSeverity`)는 **빈 문자열**.
- 현재 adk 출력: 같은 픽스처에서 `MAL-2025-342`는 종류 `vuln-lib`, 등급 **보통**으로 나오고 근거는 "점수 없음"이며, 설명문은 "알려진 보안 구멍이 있습니다"라는 일반 취약점 안내다. "고칠 버전이 없다"는 안내가 붙는다. 구현의 가정("점수가 없으면 보통, 일반 취약점 문구")와 일치한다.

### 3-3. 오프라인 DB

- 실제 npm 오프라인 DB(`npm/all.zip`)는 HEAD 요청으로 크기만 확인했다: 220,027,174바이트(약 210 MiB). **내려받지 않았다.** 대용량 데이터 내려받기이고 이번 작업에서 허락받지 않았기 때문이다. 따라서 **실제 오프라인 DB에 `MAL-` 자료가 들어 있는지는 확인하지 못했다. 확인 필요.**
- 부분 근거: OSV 저장소(GCS)의 npm 폴더에 `MAL-2025-342.json`이 개별 파일로 있다(HEAD 200, 2,606바이트). all.zip 안에도 들어 있는지는 별개의 문제다.
- osv-scanner 소스(v2.7.0)와 adk 소스에 `MAL-`을 걸러내는 코드는 없다(grep). 오프라인 DB의 `MAL-` 유무는 DB 내용에만 달려 있다.
- 대체 실험(메커니즘만 확인): `MAL-2025-342.json`과 lodash의 `GHSA-p6mc-m468-83gw.json` 두 개만 넣은 손수 만든 `npm/all.zip`을 `<db>/osv-scalibr/npm/all.zip`에 두고 `CompareOffline`으로 돌렸다. 결과는 두 항목이 모두 나오고 `MAL-` 항목의 ID, 별칭, 그룹, 빈 최대 점수가 온라인과 같다. 즉 **DB에 있으면 오프라인에서도 같은 형태로 나온다**. 이 DB는 실제 DB가 아니므로 "실제 DB에 있다"는 근거가 되지 않는다.
- 오프라인에서 `osv-scanner.toml`은 온라인과 똑같이 결과를 숨긴다(오프라인 픽스처에서 확인). 빈 `ConfigOverridePath`로 복원된다.
- 오프라인 DB 경로 규약(소스와 실험으로 확인): `LocalDBPath`를 주면 라이브러리가 그 아래 `osv-scalibr/<생태계>/all.zip`을 찾는다. `osv-scalibr/` 하위 폴더 없이 `<db>/npm/all.zip`만 두면 "no offline version of the OSV database is available"로 실패하고 이 오류는 `ERROR` 로그로 남았지만 `DoScan`은 오류 없이(`ERR=<nil>`) 돌아왔다. adk의 `quietScan`은 `ERROR` 로그를 실패로 올리므로 이 경우 deps가 실패 처리된다.

---

## 4. 구현에 미치는 영향

구현의 가정와 다르거나 구현이 따라야 하는 확인 결과다.

1. **`osv-scanner.toml` 숨김은 확인됨, 범위는 구현의 가정("IgnoredVulns만 막으면 된다")보다 넓다.** `IgnoredVulns`는 `MAL-` 항목까지 가린다. `PackageOverrides`의 `ignore = true`는 패키지를 결과에서 통째로 뺀다. 둘 다 `DoScan`이 오류 없이 돌려주고 adk는 알아채지 못한다. `--untrusted`에서 막아야 한다.
2. **`.osv-scanner.toml`(점 파일)은 v2.7.0이 읽지 않는다.** `AR-006`이 "결과를 바꿀 수 있는 파일"로 삼으려던 목록에서 이 파일은 실제로는 결과를 바꾸지 못한다. 목록에서 빼거나, 넣는다면 "읽히지 않음" 사실을 알고 문구를 정확하게 써야 한다. 버전이 바뀌면 달라질 수 있으니 osv-scanner 업그레이드 때 재확인한다.
3. **설정은 잠금 파일이 있는 폴더 단위로 적용된다.** 루트의 설정은 `sub/`의 잠금 파일에 적용되지 않고, `sub/osv-scanner.toml`은 `sub/`의 잠금 파일을 가린다. `AR-006`은 어느 깊이의 `osv-scanner.toml`도 찾아야 한다.
4. **빈 `ConfigOverridePath`가 통한다**(E3, E4b, E5, 오프라인). 실험의 빈 파일은 점검 폴더 밖의 임시 폴더에 있었다. 구현은 점검 폴더 밖의 임시 폴더에 빈 파일을 만들어 넘기고 점검 뒤 지운다. 파일을 만들지 못하거나 override 읽기 오류가 나면 `DoScan`이 오류와 `ERROR` 로그를 내므로, `--untrusted`에서 막지 못하면 `deps`를 실패로 기록한다는 전제의 경로(`--strict`에서 종료 코드 2)와 자연스럽게 이어진다. 임시 파일은 점검 대상 폴더 안이 아니어야 한다. 덧붙여, override를 주면 저장소의 `osv-scanner.toml`은 아예 읽히지 않으므로 깨진 저장소 설정이 만드는 `ERROR` 로그(`deps` 실패)도 사라진다(시험함, 2-2 추가 항목). 반대로 `--untrusted` 없이는 깨진 저장소 설정이 결과를 숨기지 못하고 `deps`를 실패시킨다.
5. **gitleaks는 `.gitleaksignore`와 `.gitleaks.toml`을 읽지 않는다.** 현재 adk는 두 경로로 숨겨지지 않는다(현재 파일, 기록 모두). 따로 막을 코드가 필요 없고, 테스트로 "숨기지 못함"을 고정해 두면 충분하다. 설정 파일이 있다는 사실 알림(`AR-006`)을 `.gitleaksignore`, `.gitleaks.toml`까지 넓힐지는 선택이다.
6. **`gitleaks:allow` 줄 안 표시는 현재 adk에서 결과를 숨긴다**(현재 파일, 기록 모두, 경고 없음). `--untrusted`가 없을 때의 동작을 바꾸지 않는다는 제약상 그대로 두되, `--untrusted`에서는 두 `Detector`(파일, 기록) 모두 `IgnoreGitleaksAllow = true`로 설정하면 복원된다(공개 필드, 임시 프로그램으로 확인). 이 필드가 없는 gitleaks 버전으로 바뀌면 컴파일 단계에서 드러난다.
7. **`MAL-`은 온라인 `DoScan`에서 나온다.** 그룹 `IDs`에 `MAL-2025-342`가 있고 GHSA와 SNYK ID는 별칭이다. 최대 점수가 빈 문자열이라 지금은 등급이 보통, 종류가 `vuln-lib`이다. "ID나 별칭이 `MAL-`로 시작하면 악성 패키지로 본다"는 판정 전제는 이 구조에서 `IDs`와 `Aliases` 양쪽을 보면 된다(샘플 하나에서는 ID 쪽에 `MAL-`이 있었고, 별칭에만 `MAL-`이 있는 경우는 시험하지 못했다. 확인 필요). "`DoScan`에 `MAL-`이 나오지 않으면 별도 조회 없이 README에서 약속을 뺀다"는 분기 전제는 온라인에서는 해당하지 않는다.
8. **오프라인 DB의 `MAL-` 포함 여부는 확인하지 못했다.** 220 MB 내려받기를 하지 않았다. 시험 결과와 무관하게 `--offline`에서 "악성 패키지 점검은 오프라인 DB 내용에 달려 있습니다" 경고를 유지한다. README에 "오프라인에서도 악성 패키지를 찾는다"고 쓰지 않는다. 오프라인 DB 형식 규약(`osv-scalibr/<생태계>/all.zip`)은 `--osv-db` 문서화에 쓸 수 있다.
9. **Claude Code 훅의 신뢰 규칙은 아래처럼 구체적으로 쓸 수 있다.** 구현 때 확인하기로 미뤄 둔 항목이었고, 확인 결과: 대화형은 신뢰 대화상자 수락 전에 훅을 실행하지 않고, `-p`·SDK는 한 번도 신뢰하지 않은 폴더의 `.claude/settings.json` 훅을 실행한다. 안내 문구는 "Claude Code를 `-p`로 쓰거나 신뢰를 누르기 전에 확인하세요" 방향이 맞다. 같은 설정 파일의 `env` 블록과 `apiKeyHelper` 같은 도우미 명령도 `-p`에서 쓰인다고 적혀 있고, `.mcp.json`의 `headersHelper`는 임의 셸 명령이다. `AR-004`는 `hooks`와 서버 `command`에 더해 도우미 명령, `.claude/settings.local.json`, 서버의 `headersHelper`와 `url`, `.vscode/mcp.json`도 보여 준다(1-7, 1-7b). 일부의 실행 시점은 확인하지 못해 설명에 "자동 실행 여부 확인 필요"로 적는다.
10. **`.mcp.json`은 `-p`에서 묻지 않고 연결된다**(구현의 가정와 같다). 승인은 대화형에서만 있고, 저장소가 커밋한 자체 승인은 인정되지 않는다.
11. **`*.code-workspace`의 `tasks`는 후속 과제.** 공식 문서로 `folderOpen` 자동 실행을 확인하지 못했다(1-3).
12. **Dev Containers 안내에 승인이 있다고 쓰지 않는다.** 참조 문서에 승인 설명이 없다(1-5). VS Code가 컨테이너에 붙을 때의 신뢰는 VS Code 문서 쪽 설명(컨테이너 연결은 자동 신뢰)이 있으나, 이것이 Dev Containers 확장의 동작에 그대로 적용되는지는 확인하지 못했다. 확인 필요.
13. **Cursor는 시작 시점 확인 필요**(1-8). 보안 페이지에 MCP 연결 승인이 있다고 적혀 있으나 시작 시점과의 관계는 불명이다. 파일이 있으면 명령을 보여 주기만 한다.
14. **npm `AR-005` 대상 스크립트 목록 보강 여부.** 생명주기 표상 `npm install`, `npm ci`는 `preinstall`, `install`, `postinstall`, `prepare` 외에 `prepublish`(옛 이름), `preprepare`, `postprepare`도 실행한다고 나온다. `AR-005`가 보려던 4개만 보면 이 셋을 놓친다. 포함할지는 구현자가 정한다.
15. **Microsoft 두 글은 요약 도구로만 읽었다.** 첫 글은 `tasks.json`을 이름으로 말하지 않는 것으로 요약된다. 문서나 README에 이 글들을 근거로 쓸 때는 "신뢰하면 작업 설정이 실행된다"는 수준까지만 쓰고, 정확한 문구는 원문 확인 후에 쓴다.
16. **VS Code 안내 문구는 공식 문서와 일치한다.** 신뢰하지 않은 폴더에서는 자동 작업이 실행되지 않고, 기본값 `off`는 처음에 허용 여부를 묻는다. 위험은 신뢰와 허용 뒤에 있다. 구현의 가정로 잡아 둔 안내 문구("신뢰하거나 자동 작업을 허용하기 전에 명령을 확인하세요")를 그대로 써도 된다.

17. **`autorun` 증적의 가리기는 gitleaks가 알아본 값만 가린다(구현 결정).** 명령은 보이는 것이 먼저라서, 증적은 설정의 JSON 원문을 그대로 보여 주되, JSON으로 묶기 전에 문자열 값과 키를 하나씩 `secrets.MaskTextCut`에 넘겨 gitleaks가 찾은 비밀 값만 `****`로 바꾼다(`gitleaks:allow`는 면제로 보지 않는다). gitleaks가 찾은 값은 그 문자열 안에서 같은 값이 나오는 곳을 모두 바꾼다. gitleaks가 알아보지 못한 값(예: `"apiKey":"hunter2"`)은 그대로 보인다. MaskTextCut은 앞 2048바이트만 gitleaks에 넘기고, 공백이나 셸 문자(`; | & $` 등)가 든 일치는 가리지 않는다. 개인 키 블록은 gitleaks 규칙을 쓰지 않고 입력 전체에서 따로 찾는다. `-----BEGIN ... PRIVATE KEY( BLOCK)-----`(PGP 포함)부터 같은 이름의 END까지, END가 없으면 그 값의 끝까지 내용을 보지 않고 항상 가리며, 그 자리에 가렸다는 문구를 항상 보여 준다. 이 블록 안에 명령이 숨어 있을 수 있다(실제로 키로 해석되는 본문에 실행되는 명령을 넣을 수 있음을 시험으로 확인했다). 그래서 이런 값이 있는 결과는 번호와 상관없이 등급을 높음 이상, 확신도를 의심으로 올린다. 증적은 1000자에서 잘리고 표시가 붙는다. JSON은 `command`, `args`, `script`, `headersHelper`, `url`, OS별 블록을 먼저 쓰고 나머지 키를 이름순으로 쓴다. `args`의 항목은 300자, `command`, `script`, `headersHelper`, `url`이 아닌 값은 120자에서 `…(잘림)`으로 잘린다. 파일마다 가리기에 넘기는 글은 1MiB까지이고, 넘으면 멈추고 일부만 보여 준다고 알린다. `scheme://user:password@host`의 비밀번호는 셸 문장이 없을 때 가린다. 값 옆의 키 이름(`"api_key":"값"`)이나 배열의 바로 앞 요소(`"--api-key","값"`)가 있어야 gitleaks가 알아보는 값도 같은 방식으로 가린다. 단 `/`, `\`, `.`이 든 값은 프로그램 경로일 수 있어 이 방식으로 가리지 않는다(`python3 -X token evil.py`). 작업의 `options.env`는 이름에 token, password, passwd, pwd, pass, secret, key, apikey, auth, credential이 있으면 값을 가린다. adk가 키로 알아보지 못한 값은 명령에 그대로 보인다(예: `--password hunter2`). 이 증적은 비밀 점검이 아니며 secrets 점검이 따로 한다. 숫자가 없는 값(예: `glpat-evil-package-name`)은 패키지 이름일 수 있어 가리지 않는다.

18. **`.gitignore`도 의존성 결과를 숨긴다.** osv-scanner는 `UseGitignore: !actions.NoIgnore`로 걷는다. 커밋된 잠금 파일이어도 `.gitignore`에 적히면 건너뛰고, adk는 "잠금 파일을 찾지 못했다"고만 알린다(손수 만든 오프라인 DB로 시험). `--untrusted`는 `NoIgnore`를 켠다. 옵션이 없을 때는 동작을 바꾸지 않는다.

19. **git 기록 점검은 저장소 설정으로 숨길 수 있다.** `.gitattributes`(커밋, 작업 폴더, `.git/info/attributes`, `core.attributesFile`)의 `-diff`와 `binary`, `diff.<드라이버>.binary`, `core.bigFileThreshold`, 대체 참조, `color.ui`/`color.diff`, `log.showRoot=false`로 시험했다. `--untrusted`는 `--text --no-color`, `GIT_NO_REPLACE_OBJECTS=1`, `log.showRoot=true`로 모두 되살린다. `.git/shallow`와 이력 자체를 고쳐 쓰는 것은 막지 않는다.

## 5. 확인하지 못한 것

- 실제 npm 오프라인 DB에 `MAL-` 자료가 들어 있는지 (내려받지 않음, 220,027,174바이트).
- 작업공간 파일(`*.code-workspace`)의 `tasks`에서 `folderOpen`이 동작하는지.
- Cursor 프로젝트 MCP 서버의 시작 시점.
- Microsoft 두 글의 원문 문구 (직접 접속은 403/502).
- OpenSSF 글의 원문 (요약 도구만).
- 별칭에만 `MAL-`이 있는 경우의 `DoScan` 결과.
- 다른 생태계(PyPI 등)의 `MAL-` 항목 모양.
- Claude Code settings의 `statusLine` 등 도우미 필드가 `-p`에서 실행되는지와 정확한 시점, 커밋된 `.claude/settings.local.json`이 쓰이는지 (1-7).
- VS Code `.vscode/mcp.json` 서버가 채팅 메시지 없이 폴더를 여는 것만으로 시작되는지 (1-7b).
