# FastAPI: 토스페이먼츠 웹훅 검증하기

아래는 공식 문서의 검증 절차(서명 검증, 결제 조회)를 FastAPI로 옮긴 **예시**입니다. 공식 SDK 코드가 아니며, 보안 키 이름(`TOSS_SECURITY_KEY`)과 `httpx` 사용은 예시를 위한 선택입니다. 보안 키는 개발자센터의 "API 개별 키 > 보안 키"에서 확인하고, 코드에 직접 쓰지 말고 환경 변수로 넣으세요.

**보안 키 사용 방식 (직접 확인함, 2026-11-04)**: 공식 문서는 "보안 키로 HMAC SHA-256 해싱"이라고만 합니다. 테스트 상점에서 실제 웹훅 2건(`DEPOSIT_CALLBACK`, `PAYMENT_STATUS_CHANGED`)을 받아 확인해 보니, 보안 키(64자 16진수 문자열)를 **문자열 그대로** 키로 써야 서명이 맞았고, 16진수로 디코딩하면 맞지 않았습니다. 아래 예시는 이 방식을 씁니다.

```python
import base64
import hashlib
import hmac
import os

import httpx
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


def signature_ok(raw: bytes, headers) -> bool:
    sent_at = headers.get("tosspayments-webhook-transmission-time", "")
    header = headers.get("tosspayments-webhook-signature", "")
    key = os.environ["TOSS_SECURITY_KEY"].encode()
    expected = hmac.new(key, raw + b":" + sent_at.encode(), hashlib.sha256).digest()
    # 서명이 여러 개일 수 있음(`,` 구분). 각각 `v1:` 뒤의 값을 base64로 디코딩해 비교
    for part in header.split(","):
        part = part.strip()
        if not part.startswith("v1:"):
            continue
        try:
            got = base64.b64decode(part[3:])
        except ValueError:
            continue
        if hmac.compare_digest(got, expected):
            return True
    return False


@router.post("/webhook/toss")
async def toss_webhook(request: Request):
    raw = await request.body()  # JSON으로 바꾸기 전의 원문 그대로
    if not signature_ok(raw, request.headers):
        raise HTTPException(status_code=401)  # 실패하면 거부

    body = await request.json()
    if body["eventType"] == "PAYMENT_STATUS_CHANGED":
        payment_key = body["data"]["paymentKey"]
        secret_key = os.environ["TOSS_SECRET_KEY"]
        auth = base64.b64encode(f"{secret_key}:".encode()).decode()
        async with httpx.AsyncClient() as client:
            res = await client.get(
                f"https://api.tosspayments.com/v1/payments/{payment_key}",
                headers={"Authorization": f"Basic {auth}"},
            )
        payment = res.json()
        # 웹훅 본문이 아니라 조회 결과로 대조 (orderId, totalAmount, status 등)
        if payment["status"] == "DONE" and payment["totalAmount"] == expected_amount(payment["orderId"]):
            mark_order_paid(payment["orderId"])
    return {"ok": True}
```

`Authorization: Basic base64(시크릿 키 + ":")` 형식은 결제 승인 API에서 확인된 API 키 인증 방식이며, 결제 조회 API(`GET /v1/payments/{paymentKey}`)에도 같은 인증을 쓰는 것으로 보고 쓴 예시입니다(문서 원문 인용 아님).

가상계좌 입금(`DEPOSIT_CALLBACK`)은 본문의 `secret`을 결제 승인 응답으로 받아 저장해 둔 `secret`과 비교하세요. 이때도 `hmac.compare_digest`처럼 시간이 일정한 비교를 쓰는 편이 안전합니다(이 부분은 예시 권장이며 공식 문서의 요구는 아닙니다).
