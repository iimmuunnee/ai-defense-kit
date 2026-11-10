# 가짜 채용 과제 (점검 도구 테스트용)

adk가 받은 저장소의 자동 실행 설정을 찾는지 시험하는 예제입니다. **실행할 필요가 없습니다.** 열지도, 설치하지도 마세요.

명령은 모두 `echo adk-test`뿐이고, 악성 패키지나 비밀 키는 들어 있지 않습니다.

```bash
adk scan testdata/untrusted/fake-assignment --untrusted
```

`.adkignore`에는 `.vscode/tasks.json`의 결과(`AR-001`) 지문이 적혀 있습니다. `--untrusted` 없이 점검하면 그 결과가 숨겨지고 경고가 나오며, `--untrusted`를 쓰면 다시 나옵니다.

잠금 파일에 패키지가 하나도 없어서, 의존성 점검이 패키지를 찾지 못했다는 경고(`의존성 잠금 파일을 찾지 못해 ...`)를 내는 것이 정상입니다.
