# FastAPI: 카카오 로그인에 state 붙이기

무작위 값을 세션에 저장하고 요청에 `state`로 보냅니다. 콜백에서는 두 값을 비교합니다. (`SessionMiddleware`가 설정되어 있어야 합니다.)

```python
import os
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/login")
def login(request: Request):
    csrf = secrets.token_urlsafe(16)
    request.session["oauth_state"] = csrf
    query = urlencode({
        "response_type": "code",
        "client_id": os.environ["KAKAO_CLIENT_ID"],
        "redirect_uri": os.environ["KAKAO_REDIRECT_URI"],
        "state": csrf,
    })
    return RedirectResponse(f"https://kauth.kakao.com/oauth/authorize?{query}")


@router.get("/callback")
def callback(request: Request, state: str = ""):
    saved = request.session.pop("oauth_state", None)
    if not saved or not secrets.compare_digest(state, saved):  # 콜백에서 꼭 비교
        raise HTTPException(status_code=400, detail="잘못된 로그인 요청")
    # 여기서부터 code로 토큰을 받는 단계를 진행
```
