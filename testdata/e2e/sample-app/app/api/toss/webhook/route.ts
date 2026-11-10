export async function POST(request: Request) {
  const body = await request.json();
  if (body.eventType === "PAYMENT_STATUS_CHANGED") {
    await markOrderPaid(body.data.orderId, body.data.totalAmount);
  }
  return new Response("ok");
}
