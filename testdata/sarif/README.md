# SARIF 스키마

`sarif-schema-2.1.0.json`은 SARIF 2.1.0의 공식 JSON 스키마입니다. 테스트가 네트워크 없이 `adk-report.sarif` 출력을 검증하는 데 씁니다.

- 출처: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json (OASIS)
- 받은 날짜: 2026-11-05
- 파일 안의 `$id`는 `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`입니다. 파일은 수정하지 않았습니다.
- 사용처: `internal/report/sarif_test.go`의 `validateSARIF`
