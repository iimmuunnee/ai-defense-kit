# Next.js: 포트원 웹훅 검증하기

`npm install @portone/server-sdk` 후, 본문을 `request.json()`이 아니라 `request.text()`로 읽어 검증합니다.

```ts
import { Webhook } from "@portone/server-sdk";

export async function POST(request: Request) {
  const rawBody = await request.text(); // JSON으로 바꾸기 전의 원문 그대로
  let webhook;
  try {
    webhook = await Webhook.verify(
      process.env.PORTONE_WEBHOOK_SECRET!,
      rawBody,
      Object.fromEntries(request.headers),
    );
  } catch {
    return new Response("웹훅 검증 실패", { status: 400 });
  }
  // 검증이 끝난 뒤에만 주문을 완료 처리
  return new Response("ok");
}
```
