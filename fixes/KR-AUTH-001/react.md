# React: 카카오 로그인에 state 붙이기

로그인을 시작할 때 무작위 값을 만들어 저장하고, 요청에 `state`로 함께 보냅니다. 돌아왔을 때 두 값이 같은지 꼭 비교하세요.

```ts
// 로그인 버튼
export function login() {
  const csrf = crypto.randomUUID();
  sessionStorage.setItem("oauth_state", csrf);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: import.meta.env.VITE_KAKAO_CLIENT_ID,
    redirect_uri: import.meta.env.VITE_KAKAO_REDIRECT_URI,
    state: csrf,
  });
  location.href = `https://kauth.kakao.com/oauth/authorize?${params}`;
}
```

```ts
// 콜백 화면 (꼭 비교하세요)
const params = new URLSearchParams(location.search);
const saved = sessionStorage.getItem("oauth_state");
sessionStorage.removeItem("oauth_state");
if (!params.get("state") || params.get("state") !== saved) {
  throw new Error("잘못된 로그인 요청");
}
// 여기서부터 code를 내 서버로 보내 토큰을 받습니다
```

예시는 Vite 기준입니다. Create React App은 `process.env.REACT_APP_...`로 읽습니다. 토큰을 받는 단계에는 비밀 값이 필요하므로 브라우저가 아니라 서버에서 처리하세요.
