from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/webhook/portone")
async def portone_webhook(request: Request):
    body = await request.json()
    if body["type"] == "Transaction.Paid":
        mark_order_paid(body["data"]["paymentId"])
    return {"ok": True}
