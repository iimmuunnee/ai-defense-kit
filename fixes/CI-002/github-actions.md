`uses`를 커밋 해시로 바꿉니다. `<...>`는 내 환경에 맞게 바꾸세요.

바꾸기 전:

```yaml
      - uses: owner/some-action@v3
```

바꾼 뒤(해시는 40자리, 주석에 버전을 남깁니다):

```yaml
      - uses: owner/some-action@<커밋 해시 40자> # v3
```

1. 그 액션 저장소의 태그(Releases 또는 Tags 화면)에서 쓰려는 버전이 가리키는 커밋 해시를 확인합니다. 주석이 달린 태그(annotated tag)는 태그 자체의 해시와 가리키는 커밋의 해시가 다를 수 있으니, 커밋 해시를 쓰세요.
2. 재사용 워크플로도 같습니다.

```yaml
jobs:
  call:
    uses: <소유자>/<저장소>/.github/workflows/build.yml@<커밋 해시 40자>
```

3. 도커 이미지는 다이제스트로 고정합니다.

```yaml
      - uses: docker://<이미지>@sha256:<다이제스트 64자>
```

4. 해시를 직접 올리지 않아도 되도록 `.github/dependabot.yml`에 아래를 추가하세요.

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot이 해시로 고정한 `uses`도 새 버전이 나오면 갱신합니다. 갱신 풀 리퀘스트는 합치기 전에 바뀐 내용을 읽어 보세요.

`actions/`와 `github/`의 액션은 GitHub이 관리해서 낮음으로 표시했습니다. 같은 방법으로 고정할 수 있습니다.
