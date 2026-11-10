# 개발자 컴퓨터 점검 (`adk device`)

이 컴퓨터에 배포에 쓰는 자격 증명이 파일로 그대로 저장되어 있는지 확인합니다. 점검하려는 컴퓨터에서 본인이 직접 실행하세요. 점검하는 파일은 읽기만 하고 바꾸지 않으며(쓰는 것은 `init`과 `accept`의 기준값 파일과 기록 파일뿐입니다), 네트워크에 연결하지 않습니다. 결과는 이 컴퓨터의 화면과 `--out` 폴더에만 남습니다.

```
adk device [--format md,json,sarif] [--out <폴더>] [--fail-on critical|high|medium|low|none]
adk device init   [--baseline <파일>] [그 밖의 옵션은 위와 같음]
adk device check  [--baseline <파일>] [--baseline-sha256 <값>] [그 밖의 옵션은 위와 같음]
adk device accept <key>... --note "<사유>" [--baseline <파일>] [--baseline-sha256 <값>]
adk device wallets [--dir <폴더>]... [--skip <경로>]... [--format md,json,sarif] [--out <폴더>] [--fail-on critical|high|medium|low]
```

`adk device`만 실행하면 토큰 저장 점검만 합니다. `init`과 `check`는 토큰 저장 점검에 더해, 개발 도구의 실행 파일과 자동 실행 지점을 기준값과 비교합니다(아래 "도구 바꿔치기와 자동 실행 지점"). `wallets`는 따로 도는 명령으로, 지갑 관련 파일의 위치를 목록으로 냅니다(아래 "도난 예상 목록").

## 무엇을 찾나요

| 번호 | 찾는 것 | 읽는 파일 | 등급 |
|---|---|---|---|
| `DV-001` | kubeconfig `users[].user`의 `token`, `client-key-data`, `client-key`(키 파일 경로), `password` | `KUBECONFIG`에 적힌 파일 모두, 없으면 `~/.kube/config` | 높음 |
| `DV-002` | Docker 설정 `auths.<레지스트리>`의 `auth`, `identitytoken` | `DOCKER_CONFIG` 폴더, 없으면 `~/.docker`의 `config.json` | 보통 |
| `DV-003` | `AKIA`로 시작하는 AWS 액세스 키 ID(장기 키) | `AWS_SHARED_CREDENTIALS_FILE`(없으면 `~/.aws/credentials`), `AWS_CONFIG_FILE`(없으면 `~/.aws/config`), 환경 변수 `AWS_ACCESS_KEY_ID` | 높음 |
| `DV-004` | `gh`의 `hosts.yml`에 평문으로 남은 `oauth_token` | `GH_CONFIG_DIR`, 없으면 `XDG_CONFIG_HOME/gh`, 없으면 `~/.config/gh`. Windows에서는 `%APPDATA%\GitHub CLI`도 | 높음 |

알리지 않는 형태: `exec`나 `auth-provider`로 짧은 자격 증명을 받는 kubeconfig 사용자와 `tokenFile`, Docker의 `credsStore`·`credHelpers`가 맡아 `auths`에 빈 항목만 남은 레지스트리, `ASIA`로 시작하는 AWS 임시 키, 환경 변수 `GH_TOKEN`·`GITHUB_TOKEN`(디스크에 저장된 값이 아니므로 보지 않습니다).

Docker는 `credsStore`나 `credHelpers`를 설정했어도 `auths`에 값이 적혀 있으면 `DV-002`로 알립니다. 저장소로 바꾸기 전에 쓰인 값은 파일에 그대로 남기 때문입니다. 이 경우 `docker logout <레지스트리>`로 남은 값을 지우고 `docker login <레지스트리>`로 다시 로그인해 저장소에 넣으세요. 남아 있으면 그 항목의 `auth`, `identitytoken`을 직접 지우세요. 저장소 안의 값은 읽지 않습니다.

## 값은 출력하지 않습니다

근거에는 파일 경로와 항목 위치만 나옵니다. 예: `users["dev-admin"].user.token`, `auths["registry.example.com"].auth`, `[default] aws_access_key_id`, `hosts["github.com"].oauth_token`, `env AWS_ACCESS_KEY_ID`. 값 자체도, 값의 앞부분이나 길이나 해시도 쓰지 않습니다. `DV-003`은 "AKIA 형식(장기 키)"라는 판단 이유만 적습니다. 홈 폴더 아래 경로는 `~/`로 줄여 사용자 이름이 나오지 않게 합니다. `gh`의 계정 이름은 순서 번호로 적습니다. kubeconfig 사용자는 `name`으로 적으므로(이름이 비었거나 겹치면 순서 번호), 이름에 개인 정보를 넣었다면 리포트를 나눌 때 주의하세요. 순서 번호로 적던 이전 버전에서 만든 기준값이면, 업그레이드 뒤 첫 `check`에서 kubeconfig 토큰이 새 항목으로 한 번 나올 수 있습니다. 확인한 뒤 `accept`로 받아들이세요.

파일이 깨져 읽지 못할 때도 파서의 오류 문구를 옮기지 않습니다. 그 문구에 파일 내용이 섞일 수 있기 때문입니다.

## 종료 코드

모든 명령이 따르는 표는 [사용법의 종료 코드](usage.md#종료-코드)입니다. 아래는 `adk device`에 해당하는 내용입니다. `--fail-on none`을 주면 결과가 있어도 1을 내지 않고, 읽지 못한 파일은 그대로 2입니다.

- `0`: `--fail-on`(기본 `high`) 이상인 결과가 없고, 있는 파일은 모두 읽었습니다.
- `1`: `--fail-on` 이상인 결과가 있습니다.
- `2`: 있는 파일 중 읽지 못했거나 형식을 알 수 없는 것이 있습니다(확인 못 함). 그 자리에 폴더나 일반 파일이 아닌 것(FIFO 등)이 있어도 열지 않고 확인 못 함으로 둡니다. 결과가 있어도 `--fail-on`에 못 미치면 2입니다. 옵션이 잘못되었을 때, `check`·`accept`에서 기준값 파일이 없거나 깨졌거나 `--baseline-sha256`과 다를 때, `init`에서 기준값 파일이 이미 있을 때도 2입니다.

`1`과 `2`의 조건이 함께 맞으면 `1`입니다. `init`도 같은 규칙을 따릅니다. 토큰 결과가 `--fail-on` 이상이면 1, 읽지 못한 항목만 있으면 2이며, 어느 경우에도 기준값은 저장합니다. `check`에서는 기준값에 있던 토큰이 1을 만들지 않습니다(아래 "저장된 토큰과 기준값"). 찾는 파일이 하나도 없으면 오류가 아니라 `0`이고, 리포트의 참고에 찾아본 곳을 적습니다. 다른 위치에 두었다면 해당 환경 변수를 설정한 셸에서 실행하세요.

## 저장된 토큰과 기준값 (`init`, `check`)

`init`은 찾은 토큰의 위치를 기준값에 기록합니다. 위치는 번호, 파일, 항목 이름(예: `token:DV-003 ~/.aws/credentials [default] aws_access_key_id`)이며, 값도 값의 앞부분이나 길이나 해시도 적지 않습니다. `check`는 토큰을 모두 다시 찾아 리포트에 적되, 기준값에 있던 것은 제목에 "기준값에 있던 항목"을 붙이고 종료 코드에는 반영하지 않습니다. 기준값에 없는 토큰만 `--fail-on`에 따라 종료 코드를 1로 만들고, 리포트의 참고에 `adk device accept`로 받아들일 key가 나옵니다. 그래서 장기 키를 당장 지울 수 없는 컴퓨터에서도 정기 `check`의 1은 "새로 생긴 것"을 뜻합니다. 남아 있는 토큰은 리포트에 계속 나오니 직접 줄이세요. 같은 위치에 값만 바뀐 토큰, 지운 뒤 같은 위치에 다시 생긴 토큰은 `accept`로 기준값에서 지우기 전까지 종료 코드에 반영되지 않습니다. 그래서 기준값에 있던 토큰을 찾지 못하면 `check`가 참고에 그 key를 적고 `accept`할 key에 넣습니다.

- `init`에는 비교할 이전 기준값이 없으므로 찾은 토큰이 모두 종료 코드에 반영됩니다. 이때도 기준값은 저장합니다.
- `adk device`만 실행하면 기준값을 보지 않고 모든 토큰을 종료 코드에 반영합니다.
- Windows에서는 기준값을 만들지 않으므로 `check`도 모든 토큰을 반영합니다.

## 도구 바꿔치기와 자동 실행 지점 (`init`, `check`, `accept`)

악성 패키지나 확장 프로그램은 자주 쓰는 개발 도구와 같은 이름의 파일을 `PATH` 앞쪽에 두거나, 로그인·셸 시작 때 자기 명령이 실행되게 해 둡니다. `adk device init`은 지금 상태를 기준값으로 기록하고, `adk device check`는 그 뒤에 달라진 것을 알립니다. 도구를 실행하지 않고 파일만 읽습니다.

1. 깨끗하다고 믿을 수 있는 때(새 컴퓨터를 설정한 직후 등)에 `adk device init`을 실행하세요. 기준값은 `~/.adk/device-baseline.json`(또는 `--baseline <파일>`)에 저장되고, 화면에 SHA-256이 나옵니다. 이 값을 다른 기기나 문서에 따로 적어 두세요. 기준값 파일이 이미 있으면 덮어쓰지 않습니다. 다시 만들려면 파일을 다른 곳으로 옮긴 뒤 실행하세요. 읽지 못한 항목이 있어도 기준값은 만듭니다. 그 항목은 '읽지 못함'으로 기록하고 리포트에 확인 못 함으로 적습니다(아래 "읽지 못한 항목").
2. 정기적으로 `adk device check --baseline-sha256 <적어 둔 값>`을 실행하세요. 기준값 파일이 없거나, 깨졌거나, SHA-256이 다르면 비교하지 않고 종료 코드 2로 끝납니다.
3. 확인한 변경은 `adk device accept <key>... --note "사유"`로 기준값에 반영합니다. key는 리포트의 참고에 나온 그대로(`tool:node`, `persist:~/.zshrc`, `'token:DV-004 ~/.config/gh/hosts.yml hosts["github.com"].oauth_token'`)이고, 여러 개를 한꺼번에 줄 수 있습니다. 그 순간 이 컴퓨터의 상태를 받아들이며, 운영체제 사용자, 시각, 사유, 바뀐 항목을 기준값 옆의 `adk-device-history.jsonl`에 덧붙인 뒤 기준값을 바꿉니다. 기록 파일은 덧붙이기만 합니다. 새 SHA-256이 화면에 나오니 다시 적어 두세요.

| 번호 | 찾는 것 | 등급 |
|---|---|---|
| `DV-101` | 개발 도구(`pyenv`, `brew`, `python`, `python3`, `node`, `npm`, `git`, `docker`, `kubectl`, `aws`, `gh`) 중 `PATH`에서 처음 찾은 실행 파일의 진입 경로, 심볼릭 링크 단계, 마지막 대상, 내용 SHA-256이 기준값과 다름. 새로 생기거나 사라진 도구도 포함 | 높음. 공식 업그레이드 모양이면 한 결과로 묶어 보통: 바뀐 경로(진입 경로, 링크 단계, 링크 대상, 실제 파일 위치)가 모두 Homebrew `Cellar`, pyenv `versions`, nvm `versions/node`(`NVM_DIR`), fnm `node-versions`(`FNM_DIR`) 중 한 곳 안에서 버전 폴더만 바뀌었을 때. Homebrew `node`의 `npm`처럼 마지막 파일 자리는 그대로이고 `<prefix>/lib/node_modules` 안에서 내용만 바뀐 것, pyenv가 그렇게 업그레이드될 때 함께 바뀐 pyenv shim(`PYENV_ROOT/shims`, 없으면 `~/.pyenv/shims`)도 같이 묶습니다. fnm이 셸마다 새로 만드는 `fnm_multishells/<번호>` 폴더 이름만 다른 것은 바뀐 것으로 보지 않습니다 |
| `DV-102` | Homebrew `bin`(`/opt/homebrew/bin`, `/usr/local/bin`, `/home/linuxbrew/.linuxbrew/bin`, `HOMEBREW_PREFIX/bin`)의 도구 링크가 Homebrew가 관리하는 곳(`Cellar`, `opt`, `Caskroom`, `Homebrew`, `lib/node_modules`, `/Applications/<앱>.app`) 밖을 가리킴. 폴더 링크를 모두 따라간 실제 파일 위치로 판단. `init` 때 이미 있던 것은 검토 항목으로 알리고 기준값에 기록하며, 그대로이면 다시 알리지 않음. 새로 생기거나 대상이 바뀐 것은 높음이며 `accept`로 기록할 수 있음(이때는 같은 도구의 `DV-101` 대신 나옴) | `init` 때 보통, `check` 때 높음 |
| `DV-103` | 자동 실행 지점이 추가되거나, 사라지거나, 바뀜. macOS `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`의 `*.plist`, Linux `~/.config/systemd/user`의 유닛 파일, `~/.config/autostart`의 `*.desktop`, `/etc/crontab`, `/etc/cron.d`, 사용자 크론(`/usr/bin/crontab -l`), 셸 시작 파일(`~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.bashrc`, `~/.zlogin`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.config/fish/config.fish`) | 셸 시작 파일은 보통, 나머지는 높음 |

- 실행 파일은 `PATH`의 절대 경로 폴더에서 실행 권한이 있는 일반 파일(링크면 따라간 끝)을 셸처럼 처음 것 하나만 찾습니다. 상대 경로 폴더(`.` 등)는 실행하는 폴더에 따라 달라지므로 보지 않습니다. 256MiB보다 큰 실행 파일은 해시를 계산하지 않고 "확인 못 함"으로 둡니다. 심볼릭 링크가 운영체제의 한도(Linux 40개, macOS 32개)보다 많이 이어지면 셸도 실행하지 못하므로 없는 것으로 봅니다.
- 자동 실행 지점의 근거에는 파일 경로와 "추가됨", "사라짐", "바뀜"만 나옵니다. 파일 내용이나 줄은 리포트에 쓰지 않습니다. 기준값 파일과 기록 파일에는 비교를 위해 파일 내용의 SHA-256이 남습니다.
- `crontab -l`은 PATH에서 찾지 않고 `/usr/bin/crontab`을 절대 경로로, 제한 시간을 두고 실행합니다. "no crontab for ..."는 사용자 크론이 없는 것으로 봅니다. 출력은 해시만 남기고 그대로 옮기지 않습니다. 기준값에 사용자 크론이 있는데 `/usr/bin/crontab`이 없으면 "확인 못 함"으로 둡니다. 그 밖의 이유로 `crontab -l`이 실패하면 확인 못 함으로 둡니다. 사용자 크론의 key는 공백이 있으니 따옴표로 감싸세요: `adk device accept "persist:crontab -l" --note "사유"`. `accept`는 자동 실행 지점 파일의 해시를 화면에 쓰지 않습니다.
- `init`은 도구를 찾은 `PATH`를 기준값(`env:PATH`)에 기록하고, `check`와 `accept`는 `--path`를 주지 않으면 그 `PATH`에서 도구를 찾습니다. 크론이나 launchd처럼 `PATH`가 짧은 곳에서 돌려도, nvm·fnm으로 다른 셸을 열어도 도구가 사라지거나 옮겨진 것으로 보이지 않습니다. 리포트의 참고에 어느 `PATH`를 썼는지, 지금 셸의 `PATH`와 다른지 적습니다(경로 자체는 적지 않습니다). 다르면 지금 셸의 `PATH`에서도 도구를 찾아, 기준값과 다른 파일(실제 위치나 내용이 다름)이 먼저 실행되면 `DV-101` 높음으로 알립니다. `PATH` 앞쪽 새 폴더에 같은 이름의 파일을 둔 경우가 여기에 걸립니다. 근거에는 두 `PATH`에서 찾은 파일을 함께 적습니다. 기준값 항목과 비교해 공식 업그레이드 모양이면(nvm으로 node 버전을 바꾼 경우 등) 한 결과로 묶어 보통입니다. 지금 셸의 `PATH`에서 찾지 못한 도구는 알리지 않으므로, 크론처럼 `PATH`가 짧은 곳에서는 조용합니다. `--path`를 주면 그 `PATH`만 봅니다. 셸의 `PATH`를 바꿨다면(nvm으로 다른 node 버전을 기본으로 삼는 등) `adk device check --path "$PATH"`로 확인한 뒤 `adk device accept env:PATH <달라진 tool key>... --path "$PATH" --note "사유"`로 함께 받아들이세요.
- 보통 결과(공식 업그레이드로 보이는 것, 셸 시작 파일)는 기본 `--fail-on high`에서 종료 코드를 1로 만들지 않지만, 받아들일 때까지 리포트에 계속 나옵니다. `--fail-on high`로 정기 점검을 돌리면 이런 결과로는 실패하지 않으니 리포트를 직접 보세요.

읽지 못한 항목: `init`은 읽지 못한 것이 있어도 멈추지 않고, 자동 실행 지점과 도구를 그때 본 상태 그대로 기준값에 적습니다. 해시를 계산한 일반 파일, 읽지 못함(권한 등), 링크(대상 경로만 적고, `/dev/null`처럼 일반 파일이 아닌 곳을 가리키면 열지 않음), 일반 파일 아님(FIFO, 폴더 등) 가운데 하나입니다. `systemctl --user mask`로 끈 유닛(`/dev/null`을 가리키는 링크)은 정상 상태로 기록됩니다. `check`에서 읽지 못함이 그대로이면 확인 못 함(종료 코드 2)으로 두고, 상태가 바뀌면(예: 읽을 수 있게 됨, 링크가 일반 파일로 바뀜) 다른 변경처럼 `DV-103`(도구는 `DV-101`)으로 알립니다. 보안 설정으로 `/etc/crontab`, `/etc/cron.d`를 일반 사용자가 읽지 못하게 한 컴퓨터에서는 `check`가 계속 2로 끝납니다. 토큰 파일을 읽지 못했을 때도 같아서, 리포트에 확인 못 함으로 적고 기준값은 저장합니다.

업그레이드 때 높음으로 나오는 것: 아래는 정상 업데이트여도 실행 파일이 같은 자리에서 내용만 바뀌거나 버전 폴더 밖으로 옮겨져 `DV-101`(자동 실행 지점은 `DV-103`) 높음으로 나옵니다. 업데이트한 직후 `adk device check`를 실행해 바뀐 것이 그 업데이트의 것인지 확인하고 `adk device accept`로 받아들이세요.

- Docker Desktop 업데이트: `/Applications/Docker.app` 안의 `docker`, `kubectl`이 같은 자리에서 바뀝니다.
- `apt upgrade`, `dnf upgrade`: `/usr/bin`의 `git`, `python3`, `gh`, `docker` 등이 같은 자리에서 바뀝니다.
- Homebrew가 자기 자신을 업데이트할 때(`brew update`): Apple Silicon의 `/opt/homebrew/bin/brew`는 일반 파일이라 내용만 바뀝니다.
- 제조사 프로그램의 LaunchAgents(예: Google 업데이트 프로그램의 plist): 업데이트 때 다시 쓰여 `DV-103`으로 나올 수 있습니다.
- pyenv를 Homebrew가 아닌 방법(git으로 받은 `~/.pyenv` 등)으로 업데이트한 뒤의 shim.
- snapd 업데이트: `/snap/bin`의 도구가 모두 `/usr/bin/snap`을 가리키므로 한꺼번에 바뀐 것으로 나옵니다(아래 "보지 못하는 것").

보지 못하는 것: 위 목록에 없는 도구와 자동 실행 지점(로그인 항목, 브라우저·편집기 확장, `/etc/profile.d` 등), snap으로 설치한 도구의 실제 실행 파일(`/snap/bin/kubectl`은 `/usr/bin/snap`을 가리키는 링크라 `snap` 실행 파일의 해시를 봅니다. 그래서 도구 자체가 바뀌어도 알지 못하고, snapd가 업데이트되면 snap 도구가 한꺼번에 바뀐 것으로 나옵니다), 셸 별칭과 함수, 관리자(root) 권한을 가진 악성코드가 숨긴 것, 이미 침해된 뒤에 만든 기준값(그 상태를 정상으로 봅니다), 점검과 점검 사이에 바꿨다가 되돌린 것. 같은 사용자 권한으로 `Cellar`, pyenv·nvm·fnm의 버전 폴더, `<prefix>/lib/node_modules`에 파일을 쓸 수 있는 프로그램은 공식 업그레이드 모양을 흉내 내 보통 등급으로 보이게 할 수 있습니다(버전 폴더 이름은 Homebrew의 `22.1.0`, `22.1.0_1`, pyenv의 `3.13.0`, `3.13.0t`, `3.13.0rc1`, `3.14-dev`, nvm·fnm의 `v22.1.0` 같은 모양만 인정합니다).

macOS는 CI 러너에서만 돌렸고 실제 기기에서는 확인하지 않았습니다. Linux에서는 모의 환경에서 검증했습니다.

## 도난 예상 목록 (`adk device wallets`)

정보를 훔치는 악성코드는 감염된 컴퓨터에서 지갑 확장 프로그램의 저장소, 데스크톱 지갑의 파일, 문서 폴더의 글 파일을 통째로 가져갑니다. `adk device wallets`는 이 컴퓨터에서 그렇게 가져갈 수 있는 것을 **위치만** 목록으로 보여 줍니다. 감염되기 전에 "훔칠 것"을 줄이는 데 씁니다. 파일을 옮기거나 지우지 않고, 기준값 파일도 쓰지 않습니다. Windows, macOS, Linux에서 모두 됩니다.

```
adk device wallets
adk device wallets --dir D:\메모 --dir E:\백업
adk device wallets --skip ~/Documents/GitHub --skip ~/.config/solana/id.json
```

| 번호 | 찾는 것 | 등급 |
|---|---|---|
| `DV-201` | 글 파일에 시드 문구(복구 문구)로 보이는 낱말 줄이 적혀 있음 | 치명(확신도: 의심) |
| `DV-202` | 브라우저 프로필에 지갑 확장 프로그램의 저장소 폴더가 있음 | 보통 |
| `DV-203` | 데스크톱 지갑의 키 저장 위치에 파일이 있음 | 보통 |
| `DV-204` | 잠그지 않고 저장하는 것이 기본인 키 파일이 있음(Solana CLI의 `id.json`, Sui CLI의 `sui.keystore`) | 높음 |

기본 `--fail-on high`에서 지갑을 깔아 쓰는 것(`DV-202`, `DV-203`)만으로는 종료 코드가 1이 되지 않습니다. 지갑 저장소는 보통 비밀번호로 잠겨 있고, 이 결과는 "감염되면 가져가서 비밀번호를 맞혀 볼 수 있는 것"의 목록입니다. 종료 코드는 위 "종료 코드"와 같습니다. 읽지 못한 폴더·파일이 있거나 아래 한도에 닿아 다 보지 못하면 2입니다.

`--dir <폴더>`는 시드 문구를 더 찾아볼 폴더입니다. 그 폴더가 링크(심볼릭 링크, 정션. 숨김·시스템 속성이 붙은 것도)이면 따라가지 않으므로, 조용히 지나치지 않고 사용법 오류(종료 코드 2)로 알립니다. 링크가 가리키는 실제 위치를 주세요. 클라우드에만 있어 목록이 이 컴퓨터에 없는 폴더, 종류를 알 수 없는 폴더를 줘도 종료 코드 2입니다.

`--skip <경로>`는 보지 않을 파일이나 폴더입니다(여러 번 쓸 수 있고, 리포트에 나온 `~/...` 모양 그대로 줘도 됩니다). 그 경로와 그 아래는 읽지도 알리지도 않습니다. 직접 확인을 마친 파일(문서에 실린 예시 문구, 시험망 전용 키 파일)이나 파일이 너무 많은 폴더(코드 저장소)를 뺄 때 씁니다. 뺀 경로는 매번 리포트의 참고에 "--skip으로 뺀 경로(보지 않음)"로 나옵니다. 뺀 곳에 새로 생긴 것은 알 수 없습니다.

### 출력에 나오는 것과 나오지 않는 것

나오는 것은 경로(홈 폴더 아래는 `~/`), 결과 번호와 제목, 지갑 이름, 브라우저 이름, 그리고 참고에 적는 찾아본 폴더와 파일 수입니다. 파일과 폴더의 이름은 검사하지 않고 그대로 적습니다. 이름에 비밀 값을 넣어 두었다면 그 이름이 리포트에 나옵니다.

시드 문구의 낱말, 일부, 낱말 수, 몇 번째 줄인지, 한 파일에 몇 개인지, 길이, 해시, 어느 검산이 맞았는지는 화면, 오류 출력, 리포트(md, json, sarif), 증적 파일 어디에도 나오지 않습니다. 시드 문구를 찾는 부분은 파일 내용을 받아 "있음/없음"만 돌려주고, 리포트를 만드는 부분은 경로와 그 답만 받습니다. 파일 내용은 메모리에서만 보고, 읽어 들인 버퍼를 본 뒤에 0으로 덮습니다(디스크에 쓰지 않습니다. 프로그램 언어의 메모리 관리 때문에 메모리에 흔적이 전혀 남지 않는다고까지는 말하지 못합니다). 지갑 확장 프로그램 저장소와 지갑 파일은 있는지만 보고 열지 않습니다.

### 시드 문구로 보는 조건 (`DV-201`)

1. 시드 문구 표준(BIP39)의 영어 또는 한국어 낱말 목록(2,048개, 실행 파일에 들어 있음)의 낱말이 12개 이상 끊기지 않고 이어집니다. 사이에 숫자, 쉼표, 줄바꿈은 있어도 되고, 목록에 없는 낱말이 끼면 끊깁니다. 대문자·소문자는 가리지 않습니다.
2. 번호를 세는 표시는 낱말로 치지 않습니다. 숫자에 바로 붙은 글자(`1st`, `2nd`, `1번`, `1번째`, `word1`)와, 숫자 옆에 적은 `Word`, `No`, `Number`, `단어`, `낱말`(`Word 1:`, `Word #1 -`, `1번 낱말:`, `단어 1:`)입니다. `word`, `number`는 목록 낱말이기도 해서, 글을 그대로 한 번, 이 표시를 뺀 채로 한 번 봅니다.
3. 그 안의 12·15·18·21·24개 묶음 하나가 검산 값이 맞습니다(BIP39 검산. 12개일 때는 Electrum 지갑 형식의 검산도 봅니다).
4. 사전이나 낱말 목록이 아닙니다. 낱말이 목록 순서대로(거꾸로도) 늘어선 묶음은 건너뜁니다.
5. 서로 다른 낱말이 (낱말 수 − 2)개 이상입니다(한 낱말을 되풀이한 것은 건너뜁니다).
6. 널리 공개된 문구가 아닙니다. Hardhat·Anvil의 기본 문구, Ganache의 결정적 모드 기본 문구, Truffle 4의 `truffle develop` 기본 문구(Truffle 5부터는 사용자마다 따로 만든 문구를 쓰므로 해당 없음), BIP39 공식 시험 벡터 24개(영어로 적은 것과 한국어로 적은 것 모두)는 알리지 않습니다. 이 문구들은 실행 파일에 글자로 들어 있지 않고, 낱말이 목록에서 몇 번째인지를 늘어놓은 번호 열의 SHA-256 값으로만 들어 있습니다. 번호 열은 언어와 상관없어서, 같은 문구를 영어 목록으로 적든 한국어 목록으로 적든 같은 것으로 봅니다. 한 파일의 문구가 모두 이런 것이면 결과를 내지 않고 참고에 "공개 시험 문구만 있음: 글 파일 N개"라고 적습니다. 같은 파일에 다른 문구가 하나라도 있으면 알립니다. 이 목록에 없는 예시 문구(다른 도구의 기본값, 블로그의 예시)는 알립니다. 확인한 뒤 `--skip`으로 빼세요.

여러 지갑의 문구를 한 파일에 적은 것도 찾습니다. 목록 낱말이 72개까지 이어지면 그 안의 모든 묶음을 봅니다. 그보다 길게 이어지면(한 줄에 한 낱말씩, 세 낱말씩, 한 문구씩 여러 개를 이어 적은 것) 줄 첫머리에서 시작해 줄 끝에서 끝나는 묶음을 봅니다. 960개(24낱말 문구 40개)보다 길게 이어지면 낱말 목록으로 보고, 한 줄이 정확히 12·15·18·21·24개인 줄만 봅니다.

찾아보는 폴더: 홈 폴더 바로 아래의 파일, `Desktop`, `Documents`, `Downloads`(Windows에서는 다른 드라이브나 OneDrive로 옮긴 위치도 운영체제에 물어 찾습니다. Linux에서는 `바탕화면`, `문서`, `다운로드`도), `~/OneDrive`와 환경 변수 `OneDrive`·`OneDriveConsumer`·`OneDriveCommercial`의 폴더, `~/Dropbox`, Windows와 macOS의 `~/Google Drive`, Windows의 `~/iCloudDrive`(확인 필요), macOS의 `~/Library/Mobile Documents/com~apple~CloudDocs`와 `~/Library/CloudStorage`, 그리고 `--dir`로 준 폴더. Linux의 `~/Google Drive`는 보통 네트워크 마운트라 읽으면 내려받게 되므로 기본으로는 보지 않습니다.

읽는 파일: 확장자가 없거나 `.txt .text .md .markdown .csv .tsv .json .yaml .yml .toml .ini .cfg .conf .env .log .org .html .htm .xml .bak .old`인 일반 파일. UTF-8과, 맨 앞에 표시가 있는 UTF-16(Windows 메모장의 "유니코드")을 읽습니다.

### 읽기 한도

| 한도 | 값 | 넘으면 |
|---|---|---|
| 글 파일 하나의 크기 | 1MiB | 읽지 않고 개수를 참고에 적음 |
| 폴더 깊이 | 찾아보는 폴더 아래 6단계 | 더 내려가지 않고 개수를 참고에 적음 |
| 읽는 글 파일 수 | 20,000개 | 멈추고 확인 못 함(종료 코드 2) |
| 읽는 양 | 256MiB | 멈추고 확인 못 함(종료 코드 2) |
| 살펴보는 폴더 항목 수 | 200,000개 | 멈추고 확인 못 함(종료 코드 2) |

- 링크(심볼릭 링크, Windows의 정션)는 따라가지 않고 개수만 참고에 적습니다. 찾아보는 기본 폴더 자체가 링크여도 들어가지 않고 개수에 넣습니다(예: Linux에서 `~/Documents`가 다른 디스크로 가는 링크). 그 폴더를 보려면 실제 위치를 `--dir`로 주세요. Windows가 옛 프로그램을 위해 홈 폴더마다 만들어 두는 숨김·시스템 정션(`Application Data`, `My Documents`, `My Music` 등)은 이미 찾아보는 폴더를 가리키므로 세지 않습니다. 홈 폴더 바로 아래에서는 폴더에 들어가지 않으므로 폴더를 가리키는 링크, 클라우드에만 있는 폴더, 종류를 알 수 없는 폴더도 세지 않습니다.
- 지갑 저장소와 지갑 파일은 경로 중간에 링크가 있어도 그 자리에 있는지는 봅니다(열지는 않습니다). 지갑의 키 저장 위치 자체가 링크나 정션이면(지갑 폴더를 다른 드라이브로 옮겨 둔 경우) "링크라서 따라가지 않음"을 붙여 알립니다.
- `.git`, `node_modules` 폴더에는 들어가지 않습니다.
- 한도에 닿아 멈췄다면 파일이 많은 폴더(코드 저장소 등)를 `--skip <폴더>`로 빼고 다시 실행하세요. 뺀 폴더는 보지 않습니다.
- 다른 프로그램이 잠가 두어 열지 못한 글 파일은 확인 못 함(종료 코드 2)입니다. 매번 그렇다면 그 파일을 확인한 뒤 `--skip`으로 빼세요.

### OneDrive 같은 클라우드 폴더 (Windows)

OneDrive의 "파일 주문형"을 켜면 OneDrive 폴더 안의 파일과 폴더는 모두 Windows가 "재분석 지점"이라고 부르는 특수 항목이 됩니다. 내용이 이 컴퓨터에 있는 파일도 그렇습니다. 링크와 정션도 재분석 지점이라서, 이 명령은 항목의 종류 표시(재분석 태그)와 속성을 읽어 셋을 가릅니다. 항목을 열지 않고 그 항목이 든 폴더의 목록에서 읽습니다.

| 항목 | 하는 일 |
|---|---|
| 링크, 정션 | 따라가지 않고 "링크 N개"로 셉니다 |
| 클라우드 항목인데 내용이 이 컴퓨터에 있는 파일, 목록이 있는 폴더 | 보통 파일·폴더처럼 읽습니다 |
| 클라우드에만 있는 파일(온라인 전용), 목록을 읽으면 받아 오게 되는 폴더 | 읽으면 내려받게 되므로 읽지 않고 "클라우드에만 있는 파일·폴더 N개(내려받지 않음)"로 셉니다. 그 안에 무엇이 있는지는 보지 못한 것입니다 |
| 종류를 알 수 없는 재분석 지점 | 읽지 않고 확인 못 함(종료 코드 2)으로 둡니다 |

확인한 정도: 종류를 가르는 규칙은 속성과 태그 값을 넣어 보는 시험으로만 확인했습니다. 실제 OneDrive 온라인 전용 파일이 있는 컴퓨터에서는 돌려 보지 못했습니다(확인 필요). 정션은 Windows에서 실제로 만들어 시험했습니다. 태그 값은 Windows SDK(`winnt.h`)의 `IO_REPARSE_TAG_SYMLINK`(0xA000000C), `IO_REPARSE_TAG_MOUNT_POINT`(0xA0000003), `IO_REPARSE_TAG_CLOUD`(0x9000001A)와 `_CLOUD_1`~`_CLOUD_F`(0x9000101A~0x9000F01A)입니다(Microsoft의 재분석 태그·파일 속성 문서와 Windows SDK로 대조한 값). 클라우드에만 있는지는 속성 `OFFLINE`, `RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS` 가운데 하나라도 있는지로 봅니다(파일과 폴더 모두). 찾아보는 폴더의 맨 위(문서 폴더, `--dir`로 준 폴더)가 재분석 지점이 아닌 채로 이 속성만 가진 경우에는 `RECALL_ON_OPEN`이 보이지 않을 수 있어, 그 폴더의 목록 한 번은 받아 오게 될 수 있습니다(파일 내용은 받지 않습니다). 파일은 연 뒤에 속성을 한 번 더 보고, 그사이 온라인 전용으로 바뀌었으면 읽지 않습니다. 참고에 "클라우드에만 있는 파일·폴더"가 나왔다면 그 파일들은 OneDrive에서 "이 장치에 항상 유지"로 받은 뒤 다시 실행해야 볼 수 있습니다.

macOS의 iCloud Drive 등에서 내용이 이 컴퓨터에 없는 파일도 읽지 않고 세도록 했지만(`SF_DATALESS`), 실제 기기에서 확인하지 않았습니다.

### 브라우저와 지갑 (`DV-202`, `DV-203`, `DV-204`)

Chrome 계열은 프로필 폴더마다 `Local Extension Settings/<확장 프로그램 번호>`와 `IndexedDB/chrome-extension_<확장 프로그램 번호>_...` 폴더가 있는지 봅니다. 프로필은 아래 폴더 자신과 그 바로 아래 폴더입니다. 결과는 "브라우저 × 프로필 × 지갑"마다 한 건입니다. 위치는 프로필 폴더이고, 그 지갑의 저장소 폴더들(보통 `Local Extension Settings` 하나와 `IndexedDB` 둘)은 근거에 프로필 폴더 아래 경로로 나열합니다. `--skip`으로 뺀 저장소 폴더는 나열하지 않고, 한 지갑의 폴더를 모두 빼면 그 결과는 나오지 않습니다. 데스크톱 지갑도 지갑 하나가 한 건입니다. 파일이 기본 위치 여러 곳에 있으면 위치는 아래 표에서 앞선 곳이고 나머지는 근거에 나열합니다. Markdown 리포트는 같은 번호의 설명과 수정 방법을 한 번만 적고 그 아래에 해당 결과를 나열합니다.

| 브라우저 | Windows | macOS | Linux |
|---|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` | `~/Library/Application Support/Google/Chrome` | `~/.config/google-chrome` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | `~/Library/Application Support/Microsoft Edge` | `~/.config/microsoft-edge` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` | `~/Library/Application Support/BraveSoftware/Brave-Browser` | `~/.config/BraveSoftware/Brave-Browser` |
| Chromium | `%LOCALAPPDATA%\Chromium\User Data` | `~/Library/Application Support/Chromium` | `~/.config/chromium`, `~/snap/chromium/common/chromium`(확인 필요) |
| 네이버 웨일(세 경로 모두 확인 필요) | `%LOCALAPPDATA%\Naver\Naver Whale\User Data` | `~/Library/Application Support/Naver/Whale` | `~/.config/naver-whale` |
| Opera | `%APPDATA%\Opera Software\Opera Stable` | `~/Library/Application Support/com.operasoftware.Opera` | `~/.config/opera` |
| Opera GX | `%APPDATA%\Opera Software\Opera GX Stable` | `~/Library/Application Support/com.operasoftware.OperaGX` | |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data` | `~/Library/Application Support/Vivaldi` | `~/.config/vivaldi` |
| Arc | | `~/Library/Application Support/Arc/User Data` | |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles` | `~/Library/Application Support/Firefox/Profiles` | `~/.mozilla/firefox`, `~/snap/firefox/common/.mozilla/firefox`(확인 필요) |

알아보는 지갑 확장 프로그램(Chrome 계열, 리포트에 나오는 이름): MetaMask(Chrome 웹 스토어와 Edge 추가 기능), Phantom, Coinbase Wallet, Trust Wallet, Rabby, BNB Chain Wallet(단종), TronLink, Keplr, Ronin Wallet, OKX Wallet, Kaia Wallet(옛 Kaikas), Exodus Web3, Solflare, Backpack, Slush(옛 Sui Wallet), Petra, Leather, UniSat, Zerion, Rainbow, Bitget Wallet, Coin98, Xverse, SecondFi(옛 Yoroi), Nami(단종 예정), MathWallet, Station Wallet, Guarda, Enkrypt, OneKey, Ctrl(옛 XDEFI, 단종), Temple. 단종된 지갑도 저장소가 디스크에 남아 있을 수 있어 그대로 봅니다. Firefox는 프로필의 `prefs.js`에서 확장 프로그램의 내부 번호를 읽어 `storage/default/moz-extension+++<내부 번호>` 폴더를 찾으며, MetaMask만 알아봅니다. `prefs.js`의 그 줄을 읽지 못하면 확인 못 함입니다.

데스크톱 지갑과 도구는 아래 자리에 파일이나 비어 있지 않은 폴더가 있는지 봅니다.

| 지갑 | Windows | macOS | Linux |
|---|---|---|---|
| Bitcoin Core | `%APPDATA%\Bitcoin`의 `wallet.dat`, `wallets` | `~/Library/Application Support/Bitcoin`의 같은 것 | `~/.bitcoin`의 같은 것 |
| Electrum | `%APPDATA%\Electrum\wallets` | `~/.electrum/wallets` | `~/.electrum/wallets` |
| Exodus | `%APPDATA%\Exodus\exodus.wallet` | `~/Library/Application Support/Exodus/exodus.wallet` | `~/.config/Exodus/exodus.wallet` |
| Atomic Wallet(세 경로 모두 확인 필요) | `%APPDATA%\atomic\Local Storage\leveldb` | `~/Library/Application Support/atomic/Local Storage/leveldb` | `~/.config/atomic/Local Storage/leveldb` |
| geth | `%LOCALAPPDATA%\Ethereum\keystore`, `%APPDATA%\Ethereum\keystore` | `~/Library/Ethereum/keystore` | `~/.ethereum/keystore` |
| Wasabi Wallet | `%APPDATA%\WalletWasabi\Client\Wallets` | `~/.walletwasabi/client/Wallets` | `~/.walletwasabi/client/Wallets` |
| Sparrow(`~/.local/share/sparrow`를 쓰는 설치는 보지 못함) | `%APPDATA%\Sparrow\wallets` | `~/.sparrow/wallets` | `~/.sparrow/wallets` |
| Monero GUI | `~\Documents\Monero\wallets` | `~/Monero/wallets` | `~/Monero/wallets` |
| Solana CLI (`DV-204`) | `~/.config/solana/id.json` | 같음 | 같음 |
| Sui CLI (`DV-204`) | `~/.sui/sui_config/sui.keystore` | 같음 | 같음 |

확장 프로그램 번호와 경로 목록은 2026-11-10에 적고, 같은 날 스토어 목록과 각 프로젝트의 소스·문서와 견주었습니다. "확인 필요"라고 적은 것(네이버 웨일의 세 경로, Atomic Wallet의 세 경로, snap으로 설치한 Chromium과 Firefox, Windows의 `~/iCloudDrive`)은 확인하지 못했습니다. 지갑이 이름이나 저장 위치를 바꾸거나 새 지갑이 나오면 낡습니다.

### 잘못 알리는 정도

시험이 실행 중에 만든 정상 글 파일 300개씩에서 잘못 알린 수입니다(`go test -v -run TestSeedFalseAlarmCount ./internal/device/`).

| 글의 종류 | 잘못 알린 파일 |
|---|---|
| 영어 글, 낱말 넷 중 하나가 목록 낱말 | 300개 중 0개 |
| 영어 글, 낱말 둘 중 하나가 목록 낱말 | 300개 중 1개 |
| 한 줄에 한 낱말씩 적은 낱말장, 둘 중 하나가 목록 낱말 | 300개 중 0개 |
| 번호를 붙인 낱말장(`1. x`), 둘 중 하나가 목록 낱말 | 300개 중 0개 |
| 낱말마다 `Word 1: x`처럼 적은 낱말장, 둘 중 하나가 목록 낱말 | 300개 중 3개 |
| 소스 코드, 이름 넷 중 하나가 목록 낱말 | 300개 중 0개 |
| 소스 코드, 이름 둘 중 하나가 목록 낱말 | 300개 중 1개 |
| 한국어 글(목록 낱말 셋 중 둘에 조사가 붙음) | 300개 중 0개 |
| 한 줄에 한 낱말씩 적은 낱말장, 넷 중 셋이 목록 낱말 | 300개 중 196개 |
| 목록 낱말만 무작위로 정확히 12개 적은 한 줄 | 300개 중 23개 |
| 목록 낱말만 무작위로 30개씩 적은 줄 20개 | 300개 중 300개 |

위 여덟 줄이 보통의 글에 가깝고(2,400개 중 5개), 아래 세 줄은 일부러 만든 나쁜 경우입니다. 넷 중 셋이 목록 낱말인 낱말장은 이 낱말 목록에서 낱말을 뽑아 만든 학습 자료 같은 것입니다. 보통의 영단어장은 목록 낱말의 비율이 훨씬 낮고, 뜻을 한국어로 같은 줄에 적으면 낱말이 이어지지 않습니다. 목록 낱말이 대부분인 낱말장이나 목록 낱말만 무작위로 길게 이어 적은 글은 시드 문구와 구별할 수 없어 대부분 알립니다. 12개 묶음 하나가 우연히 검산을 통과할 확률이 약 15분의 1이기 때문입니다. 보통의 글에서는 목록 낱말이 12개 이상 끊기지 않고 이어지는 일이 드뭅니다. 이 컴퓨터에 설치된 Go와 Git의 문서·소스 폴더의 글 파일 2,619개에서는 0개를 알렸습니다(2026-11-10, Windows에서 `--dir`로 잰 값).

### 보지 못하는 것

- 결과에 없다는 것은 **찾아본 범위 안에서 없다**는 뜻입니다. 리포트의 참고에 찾아본 폴더와 읽지 않은 것의 개수가 나옵니다.
- 사진·스크린샷·PDF·워드 문서·압축 파일·비밀번호 관리 프로그램 안, 메모 앱의 저장소, 위에 없는 폴더(홈 폴더의 다른 하위 폴더 포함), 1MiB보다 큰 파일, 위에 없는 확장자.
- 낱말 하나를 잘못 적은 시드 문구, 둘로 나눠 적은 것, 낱말 사이에 다른 낱말을 끼워 적은 것, 종이 카드처럼 두 칸으로 나눠 적은 것을 줄마다 옮긴 것(`1. … 13. …`처럼 1번 옆에 13번이 오는 것), 낱말의 앞 네 글자만 적은 것, 위에 없는 번호 표시(`첫째`, `one:` 등), 영어·한국어가 아닌 낱말 목록, BIP39·Electrum이 아닌 형식(Monero의 25단어, 옛 Electrum 등).
- 개인 키 문자열(16진수 64자 등). 해시 값과 구별할 수 없어 찾지 않습니다.
- 목록에 없는 지갑과 브라우저, 기본 위치가 아닌 곳에 둔 프로필과 지갑 파일, 브라우저의 휴대용 설치본.
- 지갑 저장소가 잠겨 있는지, 비밀번호가 얼마나 강한지, 그 지갑에 자산이 있는지.
- 검산이 맞는 낱말 줄이 실제로 쓰는 지갑의 것인지. 문서의 예시일 수 있으니 직접 확인하세요.
- sarif 리포트에는 참고가 들어가지 않습니다(다른 명령도 같습니다). 찾아본 폴더, 읽지 않은 것의 개수, `--skip`으로 뺀 경로는 화면과 md 리포트, 증적 파일에서 보세요.
- 이미 감염된 컴퓨터에서 돌린 결과는 믿을 수 없습니다. 이 명령은 감염 전에 가져갈 것을 줄이는 데 쓰는 것이고, 감염 여부를 판정하지 않습니다.

이 명령의 실행 파일에는 지갑 확장 프로그램 번호와 지갑 경로 목록이 들어 있습니다. 정보를 훔치는 악성코드가 가진 목록과 같은 종류라서, 백신 프로그램이 이 실행 파일을 악성코드로 잘못 판정할 수 있습니다. 개발 중(2026-11-10)에 Windows Defender가 이 기능의 Linux용 시험 실행 파일 하나를 정보 탈취 악성코드(`Trojan:Linux/Infostealer.DA!MTB`)로 판정해 막았습니다. 같은 날 Windows용 `adk` 실행 파일과 Linux용 CLI 시험 실행 파일은 막지 않았습니다. 다른 백신 제품과 배포용 빌드가 어떻게 판정되는지는 확인하지 않았습니다(확인 필요).

## `--home`, `--path` (시험용)

`--home <폴더>`를 주면 홈 폴더 대신 그 폴더 안의 기본 위치만 봅니다. 이때는 위 표의 환경 변수와 `PATH`, `HOMEBREW_PREFIX`, `PYENV_ROOT`, `NVM_DIR`, `FNM_DIR`를 하나도 읽지 않고, `/etc`, `/Library` 같은 시스템 위치와 사용자 크론도 보지 않으며 외부 명령을 실행하지 않습니다. 시험이 실제 컴퓨터를 읽지 않게 하기 위해서입니다. 도구는 `--path <PATH 목록>`으로 준 폴더에서만 찾습니다. `--home` 없이 `--path`만 주면 도구를 찾는 곳만 바뀝니다.

`adk device wallets --home <폴더>`도 그 폴더 안의 기본 위치만 봅니다. `LOCALAPPDATA`, `APPDATA`, `OneDrive` 같은 환경 변수를 읽지 않고(Windows에서는 `<폴더>\AppData\Local`, `<폴더>\AppData\Roaming`을 봅니다), 운영체제에 문서 폴더의 위치를 묻지 않습니다. `--dir`로 준 폴더는 그대로 봅니다.

## 플랫폼

토큰 저장 점검은 macOS, Linux, Windows에서 같은 파일을 봅니다. Windows에서 홈 폴더는 `%USERPROFILE%`이고, `gh`는 `%APPDATA%\GitHub CLI`도 봅니다. 권한이 없어 읽지 못한 파일은 "확인 못 함"으로 나옵니다.

도구 실행 파일과 자동 실행 지점 비교는 macOS와 Linux에서만 합니다. Windows에서는 `init`과 `check`가 토큰 저장 점검만 하고 리포트에 그 사실을 적으며, 기준값을 만들지 않습니다. `accept`는 받아들일 것이 없다고 알리고 종료 코드 2로 끝납니다.

`adk device wallets`는 Windows, macOS, Linux에서 모두 같은 일을 합니다. Windows에서는 시험과 모의 홈 폴더로 돌려 확인했고, Linux에서는 모의 환경(WSL)에서 명령 수준의 시험을 돌렸습니다. macOS는 빌드 검사(`go vet`)만 했고 실제 기기에서는 돌리지 않았습니다.

## 한계

- 결과가 없다고 이 컴퓨터에 자격 증명이 없다는 뜻이 아닙니다. 위 표의 파일과 형태만 봅니다. 운영체제의 자격 증명 저장소 안, 셸 기록, `.env` 파일, 브라우저, 다른 도구(`gcloud`, `az`, `terraform`, `npm` 등)의 설정은 보지 않습니다.
- 환경 변수는 `adk`를 실행한 그 셸의 것만 봅니다.
- 이미 침해된 컴퓨터에서 처음 실행하면, 그 상태를 정상으로 볼 수 있습니다. 이 점검은 저장된 값을 줄이는 데 쓰는 것이지 침해 여부를 판정하지 않습니다.
- 관리자 권한을 가진 악성코드는 `adk` 자체와 그 결과를 속일 수 있습니다.
- EDR(엔드포인트 탐지·대응) 제품을 대신하지 않습니다.
