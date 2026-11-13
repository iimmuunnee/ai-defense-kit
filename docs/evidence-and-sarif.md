# 증적 파일과 SARIF

## 증적 파일 `adk-evidence.json`

`--out`을 쓰면 리포트와 함께 `adk-evidence.json`을 저장합니다. 심사나 고객사 요청을 받았을 때 "이날, 이 버전으로, 이 코드를 점검했고, 이런 결과가 나왔다"를 보여 주는 점검 기록입니다. 별도 옵션은 없습니다. 같은 `--out` 폴더에 다시 저장하면 리포트처럼 덮어씁니다.

담기는 것:

- 점검 시각, adk 버전(릴리스 빌드가 아니면 `dev`), 함께 쓴 도구(osv-scanner, gitleaks)의 버전
- 점검 대상 이름(전체 경로가 아니라 폴더 이름만), git 커밋과 `dirty`
- 내장 규칙과 국내 기준 데이터의 내용 해시, 국내 기준 항목별 출처 버전과 검수 상태
- 외부 데이터(OSV, CISA KEV, `adk assets`는 crt.sh)를 썼는지, 온라인인지 오프라인인지, 언제 조회를 끝냈는지
- 실패하거나 건너뛴 점검과 경고
- 결과의 지문과 최소 정보, `.adkignore`로 숨긴 결과
- 이번 실행에서 실제로 쓴 리포트 파일의 SHA-256 (파일 이름만, 경로 없음)

비밀 키 원문과 내 PC의 전체 경로는 넣지 않습니다. `signature`는 항상 `null`입니다(전자서명은 아직 없습니다).

**증적 파일의 한계.** 파일에도 같은 문구가 들어 있습니다.

> 이 파일은 점검 기록입니다. 해시는 파일이 바뀌었는지 확인하는 용도이며 위변조를 막지 않습니다. 기준 충족을 증명하지 않으며 법률 자문이 아닙니다.

- 해시를 다시 계산해 보면 리포트가 그 뒤에 바뀌었는지는 알 수 있습니다. 하지만 증적 파일 자체는 서명이 없어 누구든 고쳐 쓸 수 있습니다.
- 일부만 점검한 결과를 전부 점검한 것처럼 보이지 않게, 건너뛴 점검과 오프라인 여부를 그대로 적습니다. 읽는 쪽도 `checks`와 `external_data`를 함께 보세요.
- 오프라인 DB를 쓴 경우 데이터가 언제 것인지 알 수 없어 `fetched_at`은 `null`입니다.
- 실행된 점검이 하나도 없어 종료 코드 2로 끝나면 리포트와 증적을 쓰지 않습니다. 증적 파일을 쓰지 못해도 종료 코드 2입니다.

**`git.dirty`의 뜻.** 하위 폴더를 점검해도 **저장소 전체**를 기준으로 합니다(`commit`이 저장소 전체를 가리키기 때문입니다).

| 값 | 뜻 |
|---|---|
| `no` | 저장소에 커밋하지 않은 변경도, 추적하지 않는 파일도 없음 |
| `yes` | 있음. **점검한 코드가 커밋과 다를 수 있음** |
| `unknown` | 확인할 수 없음. git 저장소가 아니거나 `adk assets`인 경우, 그리고 아래에 해당하는 경우 |

`unknown`이 되는 경우: 저장소에 하위 모듈(submodule)이 있을 때, `assume-unchanged`나 `skip-worktree`로 표시된 파일이 있을 때(sparse checkout 포함), 점검 폴더가 작업 트리 밖에 있을 때.

알아 둘 한계:

- `.gitignore`뿐 아니라 `.git/info/exclude`나 저장소가 지정한 `core.excludesFile`에 걸린 파일도 "무시된 파일"로 보고 세지 않습니다.
- 점검하는 저장소의 설정이 내 컴퓨터에서 명령을 실행하지 못하게 필터를 꺼서 확인합니다. 그래서 LFS처럼 clean/smudge 필터를 쓰는 저장소는 변경이 없는데도 `yes`가 나올 수 있습니다.
- 이번 실행이 쓰는 리포트는 `dirty`에 영향을 주지 않도록 리포트를 쓰기 **전에** 확인합니다. 그 밖의 파일은 빼지 않습니다.

**리포트는 저장소 밖이나 `.gitignore`에 넣은 폴더에, 날짜별로 저장하세요.**

```bash
adk scan . --format md,sarif,json --out ../adk-reports/2026-11-05
```

저장소 안에 쌓인 예전 리포트는 `dirty`를 `yes`로 만들고 다음 점검의 대상에도 들어갑니다. adk가 이것을 자동으로 걸러 내지는 않습니다.

## SARIF `adk-report.sarif`

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)은 점검 도구의 결과를 담는 표준 형식입니다. GitHub의 보안 탭(code scanning)에서 읽을 수 있습니다.

- 등급 대응: `critical`·`high`는 `error`, `medium`은 `warning`, `low`·`info`는 `note`. 규칙의 `security-severity`는 `critical` 9.5, `high` 8.0, `medium` 5.5, `low` 2.0이고 `info`에는 넣지 않습니다.
- 실제로 공격에 쓰이는 취약점(KEV)은 제목 앞에 `[실제 공격 중]`이 붙고 태그 `actively-exploited`가 달립니다.
- 제목, 설명, 수정 방법, 국내 기준 연결과 검수 상태는 한국어로 들어갑니다.
- `.adkignore`로 숨긴 결과는 넣지 않습니다. 비밀 키 원문과 전체 경로도 넣지 않습니다.
- 같은 점검 결과면 `invocations[0].endTimeUtc`(점검 시각)를 뺀 나머지가 같은 바이트로 나옵니다. `endTimeUtc`는 실행할 때마다 바뀝니다. 결과가 들어오는 순서가 달라도 정렬 기준이 같으면 규칙 순서와 `primaryLocationLineHash`의 순번이 달라지지 않게 고정합니다.
- 하위 폴더를 점검하면(`adk scan apps/web`) 경로 앞에 저장소 기준 경로를 붙여 GitHub가 파일을 찾게 합니다. git 저장소가 아니면 점검 폴더 기준입니다. 줄 번호가 0이면 위치에서 줄 정보를 뺍니다.
- 실패하거나 건너뛴 점검과 경고는 `invocations[0].toolExecutionNotifications`에 들어갑니다. 일부 점검을 건너뛴 파일도 `executionSuccessful`은 `true`일 수 있으므로, 이 값만 보고 전부 점검했다고 판단하지 마세요.
- 지문은 `partialFingerprints`에 `adkFingerprint/v1`으로, 그리고 `primaryLocationLineHash`에 `<지문>:<순번>` 형태로 함께 넣습니다. GitHub 문서는 code scanning이 `primaryLocationLineHash`만 쓴다고 합니다. GitHub가 이 값을 그대로 받아 같은 경고로 이어 주는지는 **확인 필요**(실제 업로드로만 알 수 있음)입니다. 줄이 옮겨져도 경고가 유지된다고 보장하지 않습니다.
- 같은 `SECRET-*` ID가 코드(높음)와 git 기록(중간)에서 등급이 달라, SARIF 규칙 ID는 종류를 붙여 나눕니다. 지문과 `.adkignore`는 그대로입니다.
- git 기록에만 남은 키는 파일 경로를 그대로 쓰고 커밋은 근거 문구에 적습니다. 지금 코드에 없는 파일을 가리킬 수 있습니다. GitHub에서 어떻게 보이는지는 **미확인**입니다(실제 업로드를 하지 않았습니다).

## 지문의 한계

- 지문은 가린 근거와 순번으로 만듭니다. 같은 자리의 값이 바뀌어도 지문은 같습니다. 그래서 `.adkignore`로 무시한 자리에 새 값이 들어가도 다시 알리지 않습니다.
- 값이 지문에 들어가지 않으므로, 리포트나 `.adkignore`에 적힌 지문을 다시 계산해 가려진 값을 짐작해 맞혀 볼 수 없습니다.
- 자동 실행 설정(`AR-*`)의 지문도 리포트에 나오는 근거와 순번에서 만듭니다. 근거가 가리거나 잘라 낸 부분(길이 제한을 넘는 뒷부분, 숨긴 `env`·`headers` 값 등)이 바뀌어도 지문은 바뀌지 않으므로, 그 부분만 바뀐 설정은 `.adkignore`로 무시한 뒤에도 다시 알리지 않습니다. 보이는 부분이 바뀌면 지문도 바뀝니다.
- 같은 파일에서 같은 규칙, 같은 가린 근거가 여러 번 나오면 줄 순서대로 순번을 붙여 따로 알립니다. 그 사이에 줄을 지우거나 끼워 넣으면 순번이 밀려 지문이 바뀔 수 있습니다.

## GitHub 보안 탭에 올릴 때

GitHub 공식 문서에서 확인한 것 (2026-11-05 조회):

- [SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning): `security-severity`는 보안 규칙(`@tags`에 `security`)에 권장되고 0.0 초과 10.0 이하 값이어야 합니다. 9.0 초과는 critical, 7.0~8.9 high, 4.0~6.9 medium, 0.1~3.9 low로 옮겨집니다. 파일은 gzip 압축 후 10 MB, 파일당 run 20개, run당 결과 25,000개(심각도 상위 5,000개만 포함), 규칙 25,000개까지입니다. 규칙 `name`은 255자, `shortDescription`과 `fullDescription`은 각 1024자까지입니다.
- [Uploading a SARIF file to GitHub](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github): 같은 커밋·카테고리·도구로 다시 올리면 이전 결과를 덮어쓴다고 합니다.
- [About code scanning](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning): 비공개 저장소는 GitHub Code Security(라이선스)가 켜져 있어야 합니다. 금액은 그 페이지에서 확인하지 못했습니다(**확인 필요**). 공개 저장소의 조건과 요금도 **확인 필요**입니다.

확인하지 못한 것:

- **실제 업로드를 해 보지 않았습니다.** 실제 저장소에 올려 본 적이 없어, 위 동작은 모두 문서와 테스트(공식 SARIF 2.1.0 스키마 검증 포함) 기준입니다. 보안 탭에서 어떻게 보이는지는 미확인입니다.
- GitHub가 다음 분석에 없는 경고를 자동으로 닫는지는 읽은 공식 페이지에서 명시적으로 확인하지 못했습니다(**확인 필요**). 이 문서의 업로드 안내는 이 가능성에 대비한 보수적인 안내입니다.
- 파일이 없는 경로를 가리키는 결과를 GitHub가 어떻게 처리하는지도 **확인 필요**입니다.

**자동 업로드는 `--strict`와 함께 쓰고, 종료 코드가 2면 올리지 마세요.** 종료 코드는 1이 2보다 먼저(표는 [사용법](usage.md#종료-코드))라 높음 이상 문제가 있으면 점검이 실패했어도 1이 나옵니다. 점검 실패만 보려면 `--fail-on none`을 함께 쓰세요([GitHub Actions 예시](github-actions.md)). 점검 일부가 실패하면 그 점검의 결과는 SARIF에 들어가지 않으므로, 올리면 기존 경고가 "고쳐짐"으로 보일 수 있습니다. 그런데 `--strict`는 **실패**만 종료 코드 2로 바꾸고 **건너뜀**은 바꾸지 않습니다. `--offline`으로 만든 파일이나, 건너뛴 점검(경고에 "건너뜀"이 보이는 경우)이 있는 파일은 올리지 마세요. 건너뛴 점검의 결과도 같은 이유로 빠져 있습니다. 어떤 점검이 빠졌는지는 증적 파일의 `checks`에서 볼 수 있습니다.

**`--strict`와 종료 코드 0이 "전부 점검했다"는 뜻은 아닙니다.** 일부만 점검하고도 상태가 `ok`로 끝나는 경우가 있고, 이때는 경고(`warnings`)만 남습니다. 예를 들어 git 기록을 전부 또는 일부 읽지 못한 경우(그러면 `secret-history` 결과가 빠질 수 있습니다), 잠금 파일을 찾지 못한 경우, 읽지 못해 건너뛴 파일이 있는 경우입니다. 건너뜀도 점검 하나가 통째로 빠지는 경우만 있는 것이 아니라 파일 일부만 빠질 수 있습니다. 이런 경우에도 `--strict`는 종료 코드 0을 돌려주고 SARIF의 `executionSuccessful`은 `true`로 남으며, [GitHub Actions 예시](github-actions.md)는 그대로 올립니다. 종료 코드는 바꾸지 않았습니다. 올리기 전에 증적 파일의 `checks[].warnings`와 SARIF의 `invocations[0].toolExecutionNotifications`를 확인하고, 부분 점검을 뜻하는 경고가 있으면 올리지 마세요. 경고에는 이 외에도 참고용인 것(예: 버전을 고정하지 않은 라이브러리)이 섞여 있으니 내용을 읽고 판단하세요.
