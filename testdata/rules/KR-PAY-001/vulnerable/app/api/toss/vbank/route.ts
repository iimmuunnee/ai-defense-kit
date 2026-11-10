export async function POST(req: Request) {
  const body = await req.json();
  const { orderId, status, transactionKey, secret } = body;
  if (status === "DONE") {
    await markDeposited(orderId, transactionKey, secret);
  }
  return Response.json({ ok: true });
}
