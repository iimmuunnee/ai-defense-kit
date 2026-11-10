from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/webhook/toss/vbank2")
async def toss_vbank_snake(request: Request):
    body = await request.json()
    if body["status"] == "DONE":
        mark_deposited(body["orderId"], body["transaction_key"], body["secret"])
    return {"ok": True}
