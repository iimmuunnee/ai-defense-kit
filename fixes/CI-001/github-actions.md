장기 키를 지우고 OIDC로 임시 자격 증명을 받도록 바꿉니다. 아래 값 중 `<...>`는 내 환경에 맞게 바꾸세요.

1. 작업에 `id-token: write`를 줍니다. 이 권한이 있어야 GitHub이 OIDC 토큰을 발급합니다. 다른 권한은 필요한 것만 둡니다.
2. 클라우드 쪽에 GitHub를 신뢰하는 설정을 만들고, 워크플로의 키 설정을 아래 예제로 바꿉니다.
3. 새 방식으로 배포가 되는 것을 확인한 뒤 옛 키를 비활성화하고, 사용 기록을 본 다음 삭제합니다. GitHub의 `secrets`에서도 지웁니다.

AWS (`aws-actions/configure-aws-credentials`):

```yaml
permissions:
  id-token: write   # OIDC 토큰을 받는 데 필요합니다
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@<커밋 해시 40자> # v4
        with:
          role-to-assume: arn:aws:iam::<계정 ID>:role/<역할 이름>
          aws-region: ap-northeast-2
```

AWS 쪽에는 IAM에 `token.actions.githubusercontent.com` OIDC 공급자를 만들고, 역할의 신뢰 정책에 저장소와 브랜치를 적습니다. 조건을 `repo:<소유자>/<저장소>:ref:refs/heads/main`처럼 좁게 쓰세요(환경을 쓰면 `repo:<소유자>/<저장소>:environment:<환경 이름>`). 정확한 문구는 AWS와 GitHub 공식 문서로 확인 필요합니다.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::<계정 ID>:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:<소유자>/<저장소>:ref:refs/heads/main"
      }
    }
  }]
}
```

Google Cloud (`credentials_json`를 쓰고 있었다면):

```yaml
      - uses: google-github-actions/auth@<커밋 해시 40자> # v2
        with:
          workload_identity_provider: projects/<프로젝트 번호>/locations/global/workloadIdentityPools/<풀>/providers/<공급자>
          service_account: <서비스 계정>@<프로젝트 ID>.iam.gserviceaccount.com
```

Azure (`creds`를 쓰고 있었다면): Microsoft Entra 앱 등록에 GitHub용 연동 자격 증명(federated credential)을 만든 뒤 아래처럼 씁니다.

```yaml
      - uses: azure/login@<커밋 해시 40자> # v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
```

Google Cloud와 Azure의 설정 순서와 입력 이름은 각 공식 문서로 확인 필요합니다.

값이 `secrets`가 없는 식(`${{ steps.단계.outputs.키 }}` 등)이라 등급 보통, 확신도 의심으로 나온 결과는, 그 값이 앞 단계가 OIDC로 받은 임시 자격 증명인지 먼저 확인하세요. 임시 자격 증명이 맞을 때만 이 결과의 지문을 `.adkignore`에 적어 숨기세요. 다른 곳에 저장된 장기 키를 가리키는 식이라면 위 방법으로 바꾸세요.
