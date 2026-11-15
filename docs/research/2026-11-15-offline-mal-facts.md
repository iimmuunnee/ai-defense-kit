# 오프라인 DB의 악성 패키지(MAL-) 자료 확인 (2026-11-15)

## 질문

`--offline --osv-db`로 점검할 때 쓰는 OSV 오프라인 DB에 악성 패키지(`MAL-`) 자료가 들어 있는가.

## 확인한 것

- osv-scanner v2.7.0은 오프라인 DB를 `https://osv-vulnerabilities.storage.googleapis.com`에서 받는다(`pkg/osvscanner/scan.go`의 `RemoteHost`). 생태계마다 `<생태계>/all.zip`이다.
- 두 생태계의 `all.zip`에서 파일 목록(zip 중앙 디렉터리)만 HTTP 범위 요청으로 읽어 이름을 셌다. 자료 본문은 받지 않았다.

| 생태계 | 전체 항목 | `MAL-` 항목 | `MAL-2025-342` |
|---|---|---|---|
| npm | 232,471 | 224,328 | 있음 |
| PyPI | 26,923 | 12,052 | 없음 (npm 패키지라 당연) |

- 같은 버킷의 `npm/MAL-2025-342.json`도 따로 받아지는 것(HTTP 200)을 확인했다.

## 오프라인 점검을 실제로 돌려 본 것 (같은 날)

- PyPI `all.zip`(37,922,066바이트, 버킷의 Last-Modified 2026-11-15 02:48 GMT)을 받았다. 이 시점 `MAL-` 항목은 12,053건이었다.
- `MAL-` 항목 중 버전이 하나만 적힌 `myasicapi` 0.2.5(`MAL-2026-984`)를 골랐다. 대조용으로 알려진 취약 버전 `requests` 2.19.0도 넣었다. 두 줄짜리 `requirements.txt`만 만들었고 패키지는 설치하지 않았다.
- main(51d25e4)에서 만든 adk로 `adk scan . --offline --osv-db <폴더>`를 돌렸다.
  - `MAL-2026-984`가 치명(critical)으로 나왔다. 꾸러미는 `myasicapi@0.2.5`였다.
  - `requests@2.19.0`의 GHSA 공지 5건이 함께 나왔다.
  - 의존성 점검 상태는 `ok`였다. KEV를 보지 않았다는 경고와 악성 패키지 점검이 DB 내용에 달려 있다는 경고가 붙었다.
- DB 자리는 `<폴더>/osv-scalibr/PyPI/all.zip`이어야 했다. osv-scanner v2.7.0이 쓰는 osv-scalibr의 `enricher/vulnmatch/osvlocal/matcher.go`가 `osv-scalibr` 하위 폴더를 쓴다. osv-scanner의 `docs/offline-mode.md`에는 `osv-scanner/`라고 적혀 있다.
  - 같은 파일을 `<폴더>/osv-scanner/PyPI/all.zip`에 두고 돌렸더니 의존성 점검이 `failed`가 됐다(`no offline version of the OSV database is available`).
  - `--strict`를 주면 종료 코드 2가 나왔다. 결과 0건으로 조용히 끝나지는 않았다.

## 확인하지 못한 것

- npm `all.zip`(221,447,911바이트)은 받지 않아서, npm 패키지(`op-vscode@1.0.0`, `MAL-2025-342`)를 오프라인으로 찾는지는 돌려 보지 않았다. PyPI와 같은 코드로 대조하므로 같게 동작할 것으로 보지만, 확인 필요로 둔다.
- 점검 중에 네트워크를 실제로 쓰지 않았는지는 패킷으로 확인하지 않았다. osv-scanner의 `CompareOffline` 설정에 기댄다.
- 오프라인 경고 문구는 그대로 둔다. DB를 받은 뒤 새로 올라온 악성 패키지는 찾지 못하는 것이 사실이기 때문이다.
