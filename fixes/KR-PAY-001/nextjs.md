# Next.js: 토스페이먼츠 웹훅 검증하기

아래는 공식 문서의 검증 절차(서명 검증, 결제 조회)를 Next.js 라우트 핸들러로 옮긴 **예시**입니다. 공식 SDK 코드가 아니며, 보안 키 이름(`TOSS_SECURITY_KEY`, `TOSS_SECRET_KEY`)은 예시를 위한 선택입니다. 두 키 모두 `NEXT_PUBLIC_` 접두사를 붙이면 브라우저로 노출되니 붙이지 마세요.

**보안 키 사용 방식 (직접 확인함, 2026-11-04)**: 공식 문서는 "보안 키로 HMAC SHA-256 해싱"이라고만 합니다. 테스트 상점에서 실제 웹훅 2건(`DEPOSIT_CALLBACK`, `PAYMENT_STATUS_CHANGED`)을 받아 확인해 보니, 보안 키(64자 16진수 문자열)를 **문자열 그대로** 키로 써야 서명이 맞았고, 16진수로 디코딩하면 맞지 않았습니다. 아래 예시는 이 방식을 씁니다.

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function signatureOk(raw: string, headers: Headers): boolean {
  const sentAt = headers.get("tosspayments-webhook-transmission-time") ?? "";
  const header = headers.get("tosspayments-webhook-signature") ?? "";
  const expected = createHmac("sha256", process.env.TOSS_SECURITY_KEY!)
    .update(`${raw}:${sentAt}`)
    .digest();
  // 서명이 여러 개일 수 있음(`,` 구분). 각각 `v1:` 뒤의 값을 base64로 디코딩해 비교
  return header.split(",").some((part) => {
    const p = part.trim();
    if (!p.startsWith("v1:")) return false;
    const got = Buffer.from(p.slice(3), "base64");
    return got.length === expected.length && timingSafeEqual(got, expected);
  });
}

export async function POST(request: Request) {
  const raw = await request.text(); // request.json()이 아니라 원문 그대로
  if (!signatureOk(raw, request.headers)) {
    return new Response("unauthorized", { status: 401 }); // 실패하면 거부
  }

  const body = JSON.parse(raw);
  if (body.eventType === "PAYMENT_STATUS_CHANGED") {
    const auth = Buffer.from(`${process.env.TOSS_SECRET_KEY}:`).toString("base64");
    const res = await fetch(
      `https://api.tosspayments.com/v1/payments/${body.data.paymentKey}`,
      { headers: { Authorization: `Basic ${auth}` } },
    );
    const payment = await res.json();
    // 웹훅 본문이 아니라 조회 결과로 대조 (orderId, totalAmount, status 등)
    if (payment.status === "DONE" && payment.totalAmount === expectedAmount(payment.orderId)) {
      await markOrderPaid(payment.orderId);
    }
  }
  return new Response("ok");
}
```

`Authorization: Basic base64(시크릿 키 + ":")` 형식은 결제 승인 API에서 확인된 API 키 인증 방식이며, 결제 조회 API(`GET /v1/payments/{paymentKey}`)에도 같은 인증을 쓰는 것으로 보고 쓴 예시입니다(문서 원문 인용 아님).

가상계좌 입금(`DEPOSIT_CALLBACK`)은 본문의 `secret`을 결제 승인 응답으로 받아 저장해 둔 `secret`과 비교하세요.
