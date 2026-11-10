# Next.js: 카카오 로그인에 state 붙이기

로그인을 시작하는 곳에서 무작위 값을 만들어 쿠키에 저장하고, 요청에 `state`로 보냅니다. 콜백에서는 두 값을 비교합니다.

```ts
// app/login/route.ts
import { randomBytes } from "crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function GET() {
  const csrf = randomBytes(16).toString("hex");
  (await cookies()).set("oauth_state", csrf, { httpOnly: true, sameSite: "lax", secure: true });
  const params = new URLSearchParams({
    response_type: "code",
    client_id: process.env.KAKAO_CLIENT_ID!,
    redirect_uri: process.env.KAKAO_REDIRECT_URI!,
    state: csrf,
  });
  return NextResponse.redirect(`https://kauth.kakao.com/oauth/authorize?${params}`);
}
```

```ts
// app/callback/route.ts (콜백에서 꼭 비교하세요)
import { cookies } from "next/headers";

export async function GET(request: Request) {
  const state = new URL(request.url).searchParams.get("state");
  const saved = (await cookies()).get("oauth_state")?.value;
  if (!state || state !== saved) {
    return new Response("잘못된 로그인 요청", { status: 400 });
  }
  // 여기서부터 code로 토큰을 받는 단계를 진행
  return new Response("ok");
}
```
