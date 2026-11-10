# GitHub Actions에서 쓰기

PR마다 자동으로 점검하고, "높음" 이상 문제가 있으면 그 작업을 실패로 표시합니다.

예시의 액션은 adk의 `CI-002`가 알리지 않도록 커밋 해시로 고정했습니다. 해시 옆 주석의 버전은 2026-11-10에 GitHub API로 그 태그의 커밋을 확인한 것입니다. 쓰기 전에 각 액션의 릴리스에서 다시 확인하세요. `adk`도 `@latest` 대신 태그나 커밋 해시로 고정하세요. `@latest`는 실행할 때마다 다른 코드를 받을 수 있습니다.

```yaml
# .github/workflows/adk.yml
name: adk 보안 점검
on: [pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0   # git 기록에 남은 키까지 보려면 전체 기록이 필요합니다
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: "1.27"
      - run: go install github.com/iimmuunnee/ai-defense-kit/cmd/adk@<쓰려는 태그 또는 커밋 해시>
      - run: adk scan . --format md,json --out ./adk-report
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with:
          name: adk-report
          path: ./adk-report
```

위 예시의 `adk scan`은 `--fail-on`의 기본값(`high`) 때문에 높음 이상 문제가 있으면 종료 코드 1로 끝나 작업이 실패합니다. 리포트 올리기는 `if: always()`라 실패해도 실행됩니다. 종료 코드의 뜻은 [사용법](usage.md#종료-코드)의 표를 따릅니다.

SARIF를 GitHub 보안 탭에 올리려면 아래처럼 `--strict`를 쓰고, 점검이 실패했을 때(종료 코드 2)는 올리지 않게 합니다. 종료 코드는 1이 2보다 먼저라서, 높음 이상 문제가 있으면 점검이 실패했어도 1이 나옵니다. 그래서 이 예시는 `--fail-on none`으로 점검 실패만 종료 코드 2로 받고, 문제 여부는 올린 뒤 JSON 리포트로 따로 판단합니다(러너에 `jq`가 있어야 합니다). 이 예시는 실제로 올려 보지 않았습니다(미확인). `github/codeql-action/upload-sarif`의 사용법과 필요한 권한은 [공식 문서](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)로 확인하세요.

```yaml
    permissions:
      contents: read
      security-events: write   # 확인 필요: 공식 문서로 확인하세요
    steps:
      # ... checkout, setup-go, go install은 위와 같습니다
      - id: adk
        run: |
          set +e
          adk scan . --format md,json,sarif --out ./adk-report --strict --fail-on none
          code=$?
          [ "$code" -eq 0 ]   # 2(도구 오류, 점검 실패)면 여기서 멈춰 업로드하지 않습니다
      - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        with:
          sarif_file: ./adk-report/adk-report.sarif
      - run: |
          # 높음 이상 문제가 있으면 업로드한 뒤에 실패 처리합니다 (adk scan의 --fail-on high와 같은 기준)
          jq -e '[.findings[] | select(.severity == "critical" or .severity == "high")] | length == 0' ./adk-report/adk-report.json
```

`--strict`는 건너뛴 점검을 실패로 세지 않으므로 이 예시에서 `--offline`을 쓰지 마세요.

이 예시는 경고만 남는 부분 점검(git 기록을 읽지 못함, 잠금 파일 없음, 읽지 못한 파일 건너뜀 등)도 실패로 보지 않습니다. 올리기 전에 `checks[].warnings`와 `toolExecutionNotifications`를 확인하는 단계를 직접 넣어야 합니다.
