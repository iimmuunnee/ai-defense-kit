export async function POST(request: Request) {
  const body = await request.json();
  if (body.eventType === "DEPOSIT_CALLBACK") {
    // secret을 읽기만 하고 저장해 둔 값과 비교하지 않음
    const received = body.secret;
    console.log("deposit", received);
    await markDeposited(body.orderId);
  }
  return new Response("ok");
}
