`GITHUB_TOKEN`의 권한을 읽기로 줄이고, 쓰기는 필요한 작업에만 범위를 골라 줍니다.

바꾸기 전:

```yaml
permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh
```

바꾼 뒤(워크플로 전체는 읽기만, 필요한 작업만 올립니다):

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ./build.sh

  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write   # 릴리스를 만드는 이 작업에만 줍니다
    steps:
      - run: ./release.sh
```

`permissions`가 아예 없다는 정보 결과는 워크플로 맨 위에 읽기 권한을 적으면 사라집니다.

```yaml
permissions:
  contents: read
```

권한을 하나도 주고 싶지 않다면 `permissions: {}`를 씁니다. 워크플로가 저장소 내용을 받는 `actions/checkout`을 쓴다면 `contents: read`가 필요합니다.

1. 줄인 뒤 워크플로를 한 번 실행해 권한 부족으로 실패하는 단계를 찾으세요. 실패 로그에 필요한 범위가 나옵니다.
2. 필요한 범위만 해당 작업에 하나씩 더하세요.
3. 저장소 설정(Settings → Actions → General → Workflow permissions)의 기본값도 읽기 전용으로 두면 `permissions`를 빠뜨린 워크플로가 쓰기 권한을 갖지 않습니다. 조직 정책과 맞는지 확인 필요합니다.
