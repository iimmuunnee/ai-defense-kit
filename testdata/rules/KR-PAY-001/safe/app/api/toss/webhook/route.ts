import { createHmac, timingSafeEqual } from "node:crypto";

export async function POST(request: Request) {
  const raw = await request.text();
  const sigHeader = request.headers.get("tosspayments-webhook-signature") ?? "";
  const sentAt = request.headers.get("tosspayments-webhook-transmission-time") ?? "";
  const expected = createHmac("sha256", process.env.TOSS_SECURITY_KEY!).update(`${raw}:${sentAt}`).digest();
  const ok = sigHeader.split(",").some((s) => {
    const got = Buffer.from(s.replace(/^v1:/, ""), "base64");
    return got.length === expected.length && timingSafeEqual(got, expected);
  });
  if (!ok) return new Response("unauthorized", { status: 401 });
  const body = JSON.parse(raw);
  if (body.eventType === "PAYMENT_STATUS_CHANGED") await markOrderPaid(body.data.orderId);
  return new Response("ok");
}
