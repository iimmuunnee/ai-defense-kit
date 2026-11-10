# HTML: 외부 스크립트에 integrity 붙이기

스크립트 파일의 SHA-384 해시를 구해 `integrity`에 적고, `crossorigin="anonymous"`를 함께 씁니다.

```bash
curl -s https://cdn.example.test/lib.js | openssl dgst -sha384 -binary | openssl base64 -A
```

```html
<script
  src="https://cdn.example.test/lib.js"
  integrity="sha384-위에서_나온_값"
  crossorigin="anonymous"></script>
```

- 파일을 내려 주는 서버가 CORS 응답 헤더를 보내야 `crossorigin="anonymous"`와 함께 동작합니다. 해시가 다르거나 헤더가 없으면 브라우저가 스크립트를 실행하지 않으니, 적용한 뒤 브라우저 개발자 도구의 콘솔에서 확인하세요.
- 버전이 주소에 들어 있는 파일(`lib@1.2.3.js`)에 쓰세요. 주소는 그대로인데 내용이 바뀌는 파일은 해시가 어긋납니다.
- 내용이 정당하게 바뀌는 스크립트는 SRI를 쓰기 어렵습니다. 이럴 때는 파일을 내 서버로 복사해 직접 내려 주는 방법을 검토하세요.
- 이 결과가 계속 나오면 지문을 `.adkignore`에 적어 무시할 수 있습니다.
