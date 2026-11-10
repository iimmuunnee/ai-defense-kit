import os

secret = os.environ["SESSION_SECRET"]


def sign_cookie(value: str) -> str:
    return value + secret
