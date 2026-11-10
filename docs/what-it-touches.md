# adk가 읽는 것, 연결하는 곳, 쓰는 파일

도입을 검토하는 보안 담당자를 위한 한 장짜리 정리입니다. 이 문서의 내용은 소스 코드에서 HTTP 요청, 외부 명령 실행, 파일 쓰기를 하는 곳을 찾아 확인한 것만 적었습니다. 코드에서 확인하지 못한 것은 "확인 필요"로 적습니다.

## 한눈에 보기

| 명령 | 연결하는 곳 | 보내는 것 | 쓰는 파일 |
|---|---|---|---|
| `adk scan` | [OSV](https://osv.dev) API(`api.osv.dev`), [CISA KEV 목록](https://github.com/cisagov/kev-data)(`raw.githubusercontent.com`) | OSV: 잠금 파일에 적힌 라이브러리의 이름, 버전, 생태계(버전 없이 커밋으로 적힌 의존성은 커밋 해시). KEV: 목록을 내려받기만 함 | `--out` 폴더의 리포트와 `adk-evidence.json`. `--out`이 없으면 화면에만 냄 |
| `adk scan --offline` | 없음 | 없음 | 위와 같음 |
| `adk watch` | 설정한 RPC 주소(환경 변수), `web-scripts`의 페이지 호스트와 `allowed_hosts`, 웹훅 주소(`ADK_WATCH_WEBHOOK`를 설정한 경우만) | RPC: 읽기 요청. 웹 페이지: GET 요청. 웹훅: 대상 key, 결과 번호, 등급이 든 JSON | 기준값 파일(기본 `adk-watch-baseline.json`), 그 옆의 `adk-watch-history.jsonl`, `adk-watch-events.jsonl`, `--out` 폴더 |
| `adk device` | 없음 | 없음 | `~/.adk/device-baseline.json`(`init`, `accept`), 그 옆의 `adk-device-history.jsonl`, `--out` 폴더 |
| `adk assets` | [crt.sh](https://crt.sh) | 도메인 이름, User-Agent(`adk/<버전> (+저장소 주소)`) | `--out` 폴더 |
| `adk version` | 없음 | 없음 | 없음 |

사용 통계, 오류 보고, 업데이트 확인 요청은 어느 명령에도 없습니다.

## 필요한 권한

- 어느 명령도 관리자(root, Administrator) 권한을 요구하지 않습니다. 코드에 권한 상승 요청이나 권한 확인이 없습니다. 일반 사용자로 실행하세요.
- `adk device`는 `/etc/crontab`, `/etc/cron.d`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` 같은 시스템 위치를 읽기만 합니다. 일반 사용자가 읽지 못하게 설정한 컴퓨터에서는 그 항목이 "확인 못 함"(종료 코드 2)으로 나옵니다([device.md](device.md#도구-바꿔치기와-자동-실행-지점-init-check-accept)).
- 쓰는 파일은 아래 각 명령에 적은 것뿐입니다. 점검하는 파일은 바꾸지 않습니다.

## `adk scan`

**읽는 것.** 점검 폴더의 파일과 git 기록입니다. 코드를 실행하거나 설치하지 않습니다. git 기록을 읽으려고 이 컴퓨터의 `git` 명령을 실행하며, 이때 `GIT_ALLOW_PROTOCOL=none`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`을 주어 git이 원격 저장소에 연결하지 못하게 합니다.

**연결하는 곳.**

- OSV: 라이브러리 점검은 [OSV-Scanner](https://github.com/google/osv-scanner) 라이브러리로 합니다. 잠금 파일에 적힌 라이브러리의 이름, 버전, 생태계를 `api.osv.dev`에 보냅니다. 버전 없이 커밋 해시로만 적힌 의존성(git으로 받은 의존성 등)은 그 커밋 해시를 보냅니다. 파일 경로와 코드 내용은 보내지 않습니다. OSV-Scanner의 기능 중 전이 의존성 조회(deps.dev, 패키지 저장소)와 파일 경로·해시를 보내는 C/C++ 소스 탐지는 adk가 끄고, 점검하는 저장소 자체의 커밋 해시 조회와 호출 분석은 기본으로 꺼져 있어 adk가 켜지 않습니다. 이 판단은 adk가 넘기는 설정과 OSV-Scanner v2.7.0 소스의 기본 동작을 읽은 것이며, 라이브러리 안의 모든 요청 경로를 시험으로 확인하지는 않았습니다(확인 필요).
- CISA KEV: OSV 조회가 끝난 뒤 KEV 목록 JSON을 내려받습니다. 요청 본문은 없습니다.
- 잠금 파일이 없어 라이브러리를 찾지 못하면 KEV 목록은 받지 않습니다.
- 두 연결 모두 환경 변수의 프록시(`HTTP_PROXY`, `HTTPS_PROXY`)를 Go 표준 동작대로 따릅니다.

**`--offline`.** 외부에 연결하지 않습니다. `--osv-db`로 준 로컬 OSV 데이터베이스가 있을 때만 라이브러리를 점검하고, 데이터베이스를 내려받지 않습니다. KEV 표시는 하지 않습니다.

**쓰는 파일.** `--out <폴더>`를 주면 그 폴더에 `adk-report.md`, `adk-report.json`, `adk-report.sarif`(고른 형식만)와 `adk-evidence.json`을 씁니다. `--out`이 없으면 파일을 쓰지 않습니다. `--untrusted`일 때는 저장소의 `osv-scanner.toml`을 무시하려고 운영체제 임시 폴더에 빈 설정 파일(`adk-osv-*.toml`)을 만들고 점검이 끝나면 지웁니다.

## `adk watch`

**읽는 것.** 설정 파일(`adk-watch.yaml`)에 적은 대상입니다. 지갑과 컨트랙트(EVM, XRPL), 웹 페이지가 불러오는 스크립트, 저장소 폴더의 파일, 사용자가 내보낸 파드 목록 파일입니다. `kubectl`을 실행하지 않습니다.

**연결하는 곳.** 설정에 적은 곳뿐입니다([watch.md](watch.md#어디로-연결하나요)).

- `evm-wallet`, `xrpl-wallet`: `rpc_url_env`에 적은 환경 변수가 가리키는 RPC 주소. EVM은 `eth_chainId`, `eth_getCode`, `eth_getStorageAt`, `eth_call`, `eth_getBlockByNumber`, XRPL은 `account_info`, `account_objects`, `ledger`만 보냅니다. 모두 읽기 요청입니다. 리다이렉트는 따라가지 않습니다.
- `web-scripts`: 페이지 주소의 호스트와 `allowed_hosts`에 적은 호스트에만 GET 요청을 보냅니다. 리다이렉트는 이 호스트들 안에서만 따라갑니다.
- `repo-files`, `k8s-pods`: 연결하지 않습니다.
- 웹훅: 환경 변수 `ADK_WATCH_WEBHOOK`를 설정한 경우에만 그 주소로 POST합니다. 본문에는 대상 key, 결과 번호, 등급, 확신 정도가 들어가고 RPC 주소, 읽은 값, 비밀은 들어가지 않습니다.
- 환경 변수의 프록시는 `--allow-env-proxy`를 줄 때만 씁니다. 외부 연결을 프록시로만 내보내는 망에서는 이 옵션이 없으면 `evm-wallet`, `xrpl-wallet`, `web-scripts` 대상이 모두 "확인 못 함"으로 나옵니다.

**쓰는 파일.** `init`과 `accept`는 기준값 파일(기본은 실행한 폴더의 `adk-watch-baseline.json`, `--baseline`으로 바꿈)을 씁니다. `accept`는 그 옆의 `adk-watch-history.jsonl`에, `check --every`는 그 옆의 `adk-watch-events.jsonl`에 한 줄씩 덧붙입니다. `--out`을 주면 그 폴더에 리포트를 씁니다. 기준값과 기록 파일은 새로 만들 때 소유자만 읽고 쓰는 권한(0600)으로 만듭니다.

## `adk device`

**읽는 것.** 이 컴퓨터의 자격 증명 설정 파일(kubeconfig, Docker, AWS, `gh`), `PATH`에서 찾은 개발 도구 실행 파일, 셸 시작 파일과 자동 실행 지점입니다. 목록은 [device.md](device.md)에 있습니다. 값은 출력하지 않습니다.

**연결하는 곳.** 없습니다. 네트워크 코드가 이 명령의 패키지에 없습니다. macOS와 Linux의 `init`, `check`는 사용자 크론을 읽으려고 `/usr/bin/crontab -l`을 실행합니다. 다른 외부 명령은 실행하지 않습니다.

**쓰는 파일.** `init`은 `~/.adk/device-baseline.json`(`--baseline`으로 바꿈)을 만들고, 폴더가 없으면 소유자만 쓸 수 있는 권한(0700)으로 만듭니다. 이미 있으면 덮어쓰지 않습니다. `accept`는 기준값을 바꾸고 그 옆의 `adk-device-history.jsonl`에 덧붙입니다. `--out`을 주면 그 폴더에 리포트를 씁니다. Windows에서는 기준값을 만들지 않습니다.

**`adk device wallets`.** 브라우저 프로필의 지갑 확장 프로그램 저장소, 데스크톱 지갑의 키 저장 위치, 키를 암호 없이 저장하는 개발 도구 파일 자리가 있는지 보고, 문서·바탕화면·다운로드·클라우드 동기화 폴더(와 `--dir`로 준 폴더)의 글 파일 안에 시드 문구로 보이는 것이 있는지 메모리에서만 확인합니다. 출력에는 경로와 종류만 나옵니다. 연결하는 곳과 실행하는 외부 명령은 없고, 기준값을 쓰지 않으며, `--out`을 주면 그 폴더에 리포트만 씁니다. 온라인 전용 클라우드 파일은 열지 않습니다([device.md](device.md)).

## `adk assets`

**연결하는 곳.** crt.sh 하나입니다. 도메인 이름을 조회 조건으로 보내고, User-Agent에 adk 버전과 이 저장소 주소를 적습니다. 리다이렉트는 같은 호스트의 http에서 https로 가는 것만 따라갑니다. 찾은 이름에 접속하지 않고 DNS 조회도 하지 않습니다. 환경 변수의 프록시는 Go 표준 동작대로 따릅니다.

**쓰는 파일.** `--out`을 주면 그 폴더에 리포트와 증적 파일을 씁니다.

## 출력 파일을 쓰는 방식

모든 명령에 같습니다.

- 쓸 자리에 링크, 폴더, FIFO처럼 일반 파일이 아닌 것이 있으면 따라가지 않고 쓰기를 거부합니다.
- 같은 폴더의 임시 파일에 다 쓴 뒤 이름을 바꿔 넣습니다. 쓰다가 실패하면 원래 파일이 그대로 남습니다. 덮어쓴 파일은 원래 권한을 유지합니다.
- 기록 파일(`*.jsonl`)은 덧붙이기만 합니다.
- 증적 파일에는 키 원문과 내 PC의 전체 경로를 넣지 않습니다([증적 파일과 SARIF](evidence-and-sarif.md)). `watch`와 `device`의 리포트에는 RPC 주소, 웹훅 주소, 자격 증명 값을 넣지 않습니다([watch.md](watch.md), [device.md](device.md)).
