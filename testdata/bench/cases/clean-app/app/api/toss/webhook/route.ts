// 웹훅 본문을 믿지 않고, 결제 키로 토스페이먼츠에 결제 상태를 다시 조회한다.
export async function POST(request: Request) {
  const body = await request.json();
  if (body.eventType !== "PAYMENT_STATUS_CHANGED") {
    return new Response("ignored");
  }
  const paymentKey = body.data.paymentKey;
  const auth = Buffer.from(process.env.TOSS_SECRET_KEY! + ":").toString("base64");
  const res = await fetch(`https://api.tosspayments.com/v1/payments/${encodeURIComponent(paymentKey)}`, {
    headers: { Authorization: `Basic ${auth}` },
  });
  const payment = await res.json();
  if (payment.status === "DONE") {
    await markOrderPaid(payment.orderId, payment.totalAmount);
  }
  return new Response("ok");
}
