from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/webhook/toss")
async def toss_webhook(request: Request):
    body = await request.json()
    if body["eventType"] == "PAYMENT_STATUS_CHANGED":
        mark_order_paid(body["data"]["orderId"])
    return {"ok": True}
