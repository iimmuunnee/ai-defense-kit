"use client";

import * as PortOne from "@portone/browser-sdk/v2";

// 결제창만 띄우는 프론트엔드 코드. 웹훅을 받지 않으므로 검증 대상이 아니다.
export default function CheckoutPage() {
  async function pay() {
    await PortOne.requestPayment({
      storeId: process.env.NEXT_PUBLIC_PORTONE_STORE_ID!,
      channelKey: process.env.NEXT_PUBLIC_PORTONE_CHANNEL_KEY!,
      paymentId: `order-${Date.now()}`,
      orderName: "테스트 상품",
      totalAmount: 1000,
      currency: "CURRENCY_KRW",
      payMethod: "CARD",
    });
  }
  return <button onClick={pay}>결제하기</button>;
}
