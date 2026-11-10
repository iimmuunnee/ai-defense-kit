# React: 비밀 값을 서버로 옮기기

비밀 값은 접두사 없는 이름으로 서버에만 두고, 브라우저 코드는 내 서버를 호출하게 합니다.

```bash
# .env (서버에서만 읽음, 접두사 없음)
PAYMENT_SECRET_KEY=여기에-새로-발급한-값
```

```ts
// 브라우저 코드
const res = await fetch("/api/charge", { method: "POST", body: JSON.stringify(order) });
```

```ts
// 서버 코드 (백엔드나 서버리스 함수)
const secret = process.env.PAYMENT_SECRET_KEY;
```

`.env`를 저장소에 올리지 않도록 `.gitignore`도 확인하세요.
