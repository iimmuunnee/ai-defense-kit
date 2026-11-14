import os

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://shop.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

API_SECRET = os.environ["PORTONE_API_SECRET"]


@app.post("/webhook/portone")
async def portone_webhook(request: Request):
    # 웹훅 본문을 믿지 않고, 결제 번호로 포트원에 결제 상태를 다시 조회한다.
    body = await request.json()
    payment_id = body["data"]["paymentId"]
    async with httpx.AsyncClient() as client:
        res = await client.get(
            f"https://api.portone.io/payments/{payment_id}",
            headers={"Authorization": f"PortOne {API_SECRET}"},
        )
    payment = res.json()
    if payment["status"] == "PAID":
        mark_order_paid(payment_id)
    return {"ok": True}
