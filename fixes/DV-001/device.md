1. 이 사용자가 어느 클러스터의 어떤 계정인지 확인하세요. `kubectl config view --minify`는 값을 가린 채 보여 줍니다.
2. 가능하면 클라우드의 인증 플러그인으로 바꾸세요. EKS는 `aws eks update-kubeconfig`, GKE는 `gke-gcloud-auth-plugin`, AKS는 `kubelogin`이 `exec` 항목을 만들어 실행할 때마다 짧은 자격 증명을 받습니다. 직접 운영하는 클러스터라면 OIDC 로그인 플러그인을 검토하세요.
3. 고정 토큰이 꼭 필요하면 `kubectl create token`처럼 만료 시간이 있는 토큰을 쓰고, 권한은 필요한 네임스페이스와 동작으로 줄이세요.
4. 바꾼 뒤 kubeconfig에서 옛 `token`, `client-key-data`, `password`를 지우고, 클러스터 쪽에서 옛 토큰이나 인증서를 폐기하세요. 클라이언트 인증서는 클러스터가 폐기를 지원하지 않는 경우가 많으니, 그 계정의 권한(RoleBinding)을 지우는 방법을 확인하세요.
5. 이 파일이 다른 곳(백업, 공유 폴더, 저장소)에 복사된 적이 있다면 값이 새었다고 보고 새로 발급하세요.
