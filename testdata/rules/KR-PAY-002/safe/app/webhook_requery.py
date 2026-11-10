# 확인 필요: 파이썬 SDK의 정확한 이름은 공식 문서로 확인하지 못함 (테스트용 예시)
import portone_server_sdk as portone
from fastapi import APIRouter, Request

router = APIRouter()
client = portone.PortOneClient("api-secret")


@router.post("/webhook/portone-requery")
async def portone_webhook_requery(request: Request):
    # 웹훅 본문은 믿지 않고, 결제 건을 포트원 API로 다시 조회한 응답만 믿는다.
    body = await request.json()
    payment = client.get_payment(body["data"]["paymentId"])
    mark_order_paid(payment)
    return {"ok": True}
