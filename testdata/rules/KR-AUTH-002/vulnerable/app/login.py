import os

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/login/naver")
def login():
    client_id = os.environ["NAVER_CLIENT_ID"]
    redirect_uri = os.environ["NAVER_REDIRECT_URI"]
    return RedirectResponse(
        f"https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"
    )
