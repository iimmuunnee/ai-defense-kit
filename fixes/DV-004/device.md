1. `gh auth status`로 어느 계정이 어디에 저장되어 있는지 확인하세요.
2. `gh auth logout`으로 로그아웃한 뒤 `--insecure-storage` 없이 `gh auth login`으로 다시 로그인하세요. 기본값은 운영체제의 자격 증명 저장소(macOS 키체인, Windows 자격 증명 관리자, Linux의 Secret Service)에 토큰을 둡니다. Linux 서버처럼 저장소가 없으면 평문으로 떨어지니 그 환경에서 꼭 로그인해야 하는지 다시 보세요.
3. `hosts.yml`에서 `oauth_token`이 사라졌는지 확인하세요.
4. 파일이 다른 곳에 복사된 적이 있다면 GitHub 설정의 Applications(또는 Personal access tokens)에서 그 토큰을 폐기하세요. 토큰에 필요 없는 권한(`workflow`, `admin:org` 등)이 있다면 줄여서 다시 발급하세요.
