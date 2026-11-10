"use client";
import { loadTossPayments } from "@tosspayments/tosspayments-sdk";

// 결제 상태는 서버가 PAYMENT_STATUS_CHANGED 웹훅으로 받습니다. 이 화면은 결제창만 엽니다.
export default function Checkout() {
  async function pay() {
    const toss = await loadTossPayments(process.env.NEXT_PUBLIC_TOSS_CLIENT_KEY!);
    await toss.payment({ customerKey: "guest" });
  }
  return <button onClick={pay}>결제하기</button>;
}
