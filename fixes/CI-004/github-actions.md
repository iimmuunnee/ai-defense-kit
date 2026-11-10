`pull_request_target`에서 풀 리퀘스트의 코드를 내려받지 않도록 바꿉니다.

바꾸기 전(풀 리퀘스트의 코드를 받아 `secrets` 권한으로 실행하는 모양):

```yaml
on:
  pull_request_target:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<커밋 해시 40자> # v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./check.sh
```

방법 1. 코드를 실행할 필요가 없으면 `ref`를 지웁니다. 기준 브랜치의 코드를 받습니다.

```yaml
      - uses: actions/checkout@<커밋 해시 40자> # v4
```

방법 2. 풀 리퀘스트 코드를 빌드하거나 테스트해야 하면 `pull_request`를 씁니다. 포크에서 온 풀 리퀘스트에는 `secrets`가 전달되지 않고 토큰은 읽기 권한입니다.

```yaml
on:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<커밋 해시 40자> # v4
      - run: ./test.sh
```

방법 3. 풀 리퀘스트 코드를 실행한 뒤에 `secrets`나 쓰기 권한이 필요한 일(결과 댓글 달기 등)이 있으면, 앞 워크플로(`pull_request`)와 뒤 워크플로(`workflow_run`)로 나눕니다. 뒤 워크플로는 풀 리퀘스트 코드를 내려받거나 실행하지 말고, 앞 워크플로가 올린 산출물은 믿을 수 없는 입력으로 읽으세요. 자세한 수칙은 아래 GitHub Security Lab 글을 확인하세요(확인 필요).

방법 4. 이 구조를 꼭 써야 한다면 권한을 읽기로 줄이고 풀 리퀘스트 코드를 받는 작업에서 `secrets`를 쓰지 않습니다.

```yaml
permissions:
  contents: read
```

참고: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

`run:` 단계의 `gh pr checkout`, `git fetch`로 풀 리퀘스트 코드를 받는 경우는 이 점검이 보지 않으므로, 워크플로 파일을 직접 열어 확인하세요.
