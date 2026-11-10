from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.post("/webhook/toss/deposit")
async def toss_deposit(request: Request):
    body = await request.json()
    if body["eventType"] == "DEPOSIT_CALLBACK":
        saved_secret = load_saved_secret(body["orderId"])
        if body["secret"] != saved_secret:
            raise HTTPException(status_code=401)
        mark_deposited(body["orderId"])
    return {"ok": True}
