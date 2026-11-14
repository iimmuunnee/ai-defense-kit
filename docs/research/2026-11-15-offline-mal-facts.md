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

## 확인하지 못한 것

- 오프라인 DB를 실제로 내려받아 `adk scan --offline --osv-db`로 `op-vscode@1.0.0`을 점검해 `MAL-2025-342`가 나오는지는 돌려 보지 않았다(확인 필요). osv-scanner의 오프라인 비교가 `MAL-` 항목을 다른 항목과 똑같이 대조하는지는 코드로 확인하지 않았다.
- 그래서 오프라인 점검의 경고 문구는 그대로 둔다.
