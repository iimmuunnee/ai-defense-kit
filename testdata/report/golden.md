# adk 점검 리포트

- 대상: ./my-app
- 스택: fastapi, nextjs
- 점검 시각: 2026-11-04T09:30:00Z
- 도구 버전: v0.1.0
- git 커밋: 0123456789abcdef0123456789abcdef01234567

> ⚠️ 일부 점검을 하지 못했습니다
>
> - secrets: git 기록이 없어 과거 커밋은 확인하지 못함
> - deps (실패): OSV 조회 실패: network unreachable

## 지금 당장 고칠 것

1. [높음] 코드에 키가 들어 있습니다 - `config.py:3`
2. [높음] 포트원 웹훅 검증 누락 - `app/webhook.py:8`
3. [보통] 취약한 라이브러리: lodash 4.17.15 - `package-lock.json`

## 요약

| 등급 | 개수 |
| --- | --- |
| 치명 | 0 |
| 높음 | 2 |
| 보통 | 1 |
| 낮음 | 0 |
| 참고 | 1 |

## 상세

### [높음] 코드에 키가 들어 있습니다

- 번호: SECRET-generic-api-key
- 위치: `config.py:3`
- 판단: 확실
- 지문: 3333cccc4444dddd (무시하려면 .adkignore에 추가)
- 근거: `api_key = "K7Q2****"`

키가 저장소에 있으면 누구나 쓸 수 있습니다.

**수정 방법**

키를 폐기하고 환경 변수로 옮기세요.

### [높음] 포트원 웹훅 검증 누락

- 번호: KR-PAY-002
- 위치: `app/webhook.py:8`
- 판단: 의심
- 지문: 5555eeee6666ffff (무시하려면 .adkignore에 추가)

서명을 확인하지 않으면 가짜 결제 알림을 받을 수 있습니다.

**수정 방법**

Webhook.verify를 호출하세요.

**참고 링크**

- https://jsr.io/@portone/server-sdk/doc/~/Webhook

**국내 기준**

- ISMSP-2.10.4: 기준 정보 없음 (검수 전)

### [보통] 취약한 라이브러리: lodash 4.17.15

- 번호: DEP-CVE-2021-44228
- 위치: `package-lock.json`
- 판단: 확실
- 지문: 1111aaaa2222bbbb (무시하려면 .adkignore에 추가)

알려진 취약점이 있는 버전입니다.

**수정 방법**

4.17.21 이상으로 올리세요.

**참고 링크**

- https://osv.dev/GHSA-xxxx

### [참고] 참고 사항

- 번호: INFO-1
- 위치: `README.md`
- 판단: 의심

---

이 리포트는 법률 자문이 아닙니다. 국내 기준 연결은 참고용이며, 최종 판단은 전문가와 확인하세요.
