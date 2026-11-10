import os

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/login/kakao")
def login():
    client_id = os.environ["KAKAO_CLIENT_ID"]
    redirect_uri = os.environ["KAKAO_REDIRECT_URI"]
    return RedirectResponse(
        f"https://kauth.kakao.com/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"
    )
