from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/webhook/toss/vbank")
async def toss_vbank(request: Request):
    body = await request.json()
    order_id = body["orderId"]
    if body["status"] == "DONE":
        mark_deposited(order_id, body["transactionKey"], body["secret"])
    return {"ok": True}
