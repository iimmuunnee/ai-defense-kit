from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.post("/webhook/toss/vbank")
async def toss_vbank(request: Request):
    body = await request.json()
    saved_secret = load_saved_secret(body["orderId"])
    if body["secret"] != saved_secret:
        raise HTTPException(status_code=401)
    mark_deposited(body["orderId"], body["transactionKey"])
    return {"ok": True}
