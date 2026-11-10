import { NextRequest, NextResponse } from "next/server";
import * as PortOne from "@portone/server-sdk";
import { markOrderPaid } from "@/lib/orders";

// 포트원 웹훅 수신: 원문 본문을 그대로 읽은 뒤 서명을 검증한다.
export async function POST(req: NextRequest) {
  const raw = await req.text();
  let webhook: PortOne.Webhook.Webhook;
  try {
    webhook = await PortOne.Webhook.verify(
      process.env.PORTONE_WEBHOOK_SECRET!,
      raw,
      Object.fromEntries(req.headers),
    );
  } catch (e) {
    if (e instanceof PortOne.Errors.WebhookVerificationError) {
      return NextResponse.json({ error: "invalid signature" }, { status: 400 });
    }
    throw e;
  }
  if ("data" in webhook && webhook.type === "Transaction.Paid") {
    await markOrderPaid(webhook.data.paymentId);
  }
  return NextResponse.json({ ok: true });
}
