export async function POST(request: Request) {
  const body = await request.json();
  if (body.eventType === "PAYMENT_STATUS_CHANGED") {
    const auth = Buffer.from(`${process.env.TOSS_SECRET_KEY}:`).toString("base64");
    const res = await fetch(`https://api.tosspayments.com/v1/payments/${body.data.paymentKey}`, {
      headers: { Authorization: `Basic ${auth}` },
    });
    const payment = await res.json();
    if (payment.status === "DONE" && payment.totalAmount === expectedAmount(payment.orderId)) {
      await markOrderPaid(payment.orderId);
    }
  }
  return new Response("ok");
}
