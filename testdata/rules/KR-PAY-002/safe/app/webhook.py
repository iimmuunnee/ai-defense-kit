import portone_server_sdk as portone
from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/webhook/portone")
async def portone_webhook(request: Request):
    raw = (await request.body()).decode("utf-8")
    webhook = portone.webhook.verify("secret", raw, dict(request.headers))
    if isinstance(webhook, portone.webhook.WebhookTransactionPaid):
        mark_order_paid(webhook.data.payment_id)
    return {"ok": True}
