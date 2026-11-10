1. 그 키가 어느 IAM 사용자의 것이고 어떤 권한이 있는지 확인하세요. 키 자체를 출력하지 않으려면 `aws sts get-caller-identity --profile <프로필>`로 사용자를 확인할 수 있습니다.
2. 사람이 쓰는 접속은 IAM Identity Center(SSO)로 바꾸세요. `aws configure sso`로 프로필을 만들면 로그인할 때마다 임시 키를 받습니다. 프로그램이나 다른 계정에 접속할 때는 역할(`role_arn`, `source_profile`)을 쓰세요.
3. 장기 키가 꼭 필요하면 권한을 필요한 만큼으로 줄이고, MFA 조건을 걸고, 주기적으로 교체하세요.
4. 전환을 확인한 뒤 자격 증명 파일에서 그 프로필의 `aws_access_key_id`, `aws_secret_access_key`를 지우고, IAM에서 그 키를 비활성화한 다음 마지막 사용 기록을 확인하고 삭제하세요.
5. 환경 변수에서 나왔다면 셸 시작 파일(`.bashrc`, `.zshrc`, PowerShell 프로필)이나 `.env` 파일에 적어 둔 곳을 찾아 지우세요.
