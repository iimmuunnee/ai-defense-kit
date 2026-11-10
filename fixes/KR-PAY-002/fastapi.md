# FastAPI: 포트원 웹훅 검증하기

`pip install portone-server-sdk` 후, 본문을 JSON으로 바꾸기 전의 원문(`await request.body()`)으로 검증합니다.

```python
import portone_server_sdk as portone
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()
WEBHOOK_SECRET = "포트원 콘솔에서 받은 웹훅 시크릿 (환경 변수로 읽으세요)"

@router.post("/webhook/portone")
async def portone_webhook(request: Request):
    raw_body = (await request.body()).decode("utf-8")  # JSON으로 바꾸지 말고 원문 그대로
    try:
        webhook = portone.webhook.verify(WEBHOOK_SECRET, raw_body, dict(request.headers))
    except Exception:
        raise HTTPException(status_code=400, detail="웹훅 검증 실패")

    if isinstance(webhook, portone.webhook.WebhookTransactionPaid):
        ...  # 검증이 끝난 뒤에만 주문을 완료 처리
    return {"ok": True}
```
