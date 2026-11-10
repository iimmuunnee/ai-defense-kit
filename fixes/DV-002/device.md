1. 자격 증명 저장소를 쓰도록 바꾸세요. Docker Desktop은 보통 `"credsStore": "desktop"`을 씁니다. macOS는 `osxkeychain`, Windows는 `wincred`, Linux는 `pass`나 `secretservice` 도우미가 있습니다. 도우미 프로그램이 설치되어 있어야 동작합니다.
2. 클라우드 레지스트리는 전용 도우미를 `credHelpers`에 적으세요. 예: AWS ECR은 `amazon-ecr-credential-helper`(`ecr-login`), Google은 `gcloud auth configure-docker`가 설정하는 `gcloud`. 이 도우미는 짧은 토큰을 그때그때 받습니다.
3. 저장소로 바꾼 뒤에도 `config.json`의 `auths`에 예전 `auth`, `identitytoken` 값이 남아 있으면 이 결과가 계속 나옵니다. `docker logout <레지스트리>`로 파일의 값을 지운 다음 `docker login <레지스트리>`로 다시 로그인해 값이 저장소에 들어가게 하세요. 그래도 남아 있으면 그 레지스트리 항목의 `auth`, `identitytoken`을 직접 지우세요. 다시 실행해 결과가 사라졌는지 확인하세요.
4. 이 값이 다른 곳에 복사된 적이 있거나 오래 저장되어 있었다면, 레지스트리에서 비밀번호나 액세스 토큰을 새로 발급하고 옛 것을 폐기하세요. 이미지를 올릴 권한이 꼭 필요한지도 확인하세요.
