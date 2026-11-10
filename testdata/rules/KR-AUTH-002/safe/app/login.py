import os
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/login/naver")
def login(request: Request):
    csrf = secrets.token_urlsafe(16)
    request.session["oauth_state"] = csrf
    query = urlencode(
        {"response_type": "code", "client_id": os.environ["NAVER_CLIENT_ID"], "state": csrf}
    )
    return RedirectResponse(f"https://nid.naver.com/oauth2.0/authorize?{query}")
