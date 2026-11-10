import { NextRequest, NextResponse } from "next/server";
import { markOrderPaid } from "@/lib/orders";
import { portoneStoreId } from "@/lib/portone";

// 포트원 웹훅 수신 (서명 검증 없음)
export async function POST(req: NextRequest) {
  console.log("store", portoneStoreId);
  const body = await req.json();
  if (body.type === "Transaction.Paid") {
    await markOrderPaid(body.data.paymentId);
  }
  return NextResponse.json({ ok: true });
}
