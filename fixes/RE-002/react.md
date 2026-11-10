# React: 공개하면 안 되는 키를 서버로 옮기기

공개를 전제로 만든 키가 아니라면 서버에 두고, 브라우저 코드는 내 서버를 호출하게 합니다.

```ts
// 브라우저 코드
const res = await fetch("/api/search?q=" + encodeURIComponent(q));
```

```ts
// 서버 코드 (백엔드나 서버리스 함수)
const key = process.env.SEARCH_API_KEY; // VITE_나 REACT_APP_을 붙이지 않습니다
```

공개용 키라면 해당 서비스 설정에서 사용할 수 있는 도메인과 범위를 제한하세요. 이 결과가 계속 나오면 지문을 `.adkignore`에 적어 무시할 수 있습니다.
