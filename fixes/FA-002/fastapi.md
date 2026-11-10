# FastAPI: 문서 화면 다루기

먼저 기억할 것: 문서 화면을 끄는 것은 보호 수단이 아닙니다. 모든 엔드포인트에 인증을 거는 것이 우선입니다. FastAPI 공식 문서도 "Hiding your documentation user interfaces in production *shouldn't* be the way to protect your API."라고 적습니다.

## 1. 모든 엔드포인트에 인증 걸기

```python
from fastapi import Depends, FastAPI

app = FastAPI()


def require_user():
    ...  # 토큰이나 세션을 확인하고, 없거나 틀리면 401을 낸다


@app.get("/items", dependencies=[Depends(require_user)])
def list_items():
    return []
```

엔드포인트마다 빠뜨리지 않았는지 꼭 확인하세요.

## 2. 운영에서 문서가 필요 없다면: 환경 변수로 끄기

공식 문서의 조건부 OpenAPI 방식입니다. `openapi_url`을 `None`으로 만들면 `/docs`, `/redoc`, `/openapi.json`이 모두 404가 됩니다.

```python
from fastapi import FastAPI
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    openapi_url: str = ""  # 운영에서는 비워 두면 꺼짐


settings = Settings()

app = FastAPI(openapi_url=settings.openapi_url or None)
```

개발 환경에서만 `OPENAPI_URL=/openapi.json`으로 켜면 됩니다. 이 규칙은 `openapi_url=` 뒤에 변수나 설정 값이 오면 끈 것으로 봅니다.

## 3. 간단히 항상 끄기

```python
app = FastAPI(docs_url=None, redoc_url=None)
```

`docs_url=None`은 `/docs`, `redoc_url=None`은 `/redoc`만 끕니다. `/openapi.json`까지 끄려면 `openapi_url=None`을 쓰세요(이때 두 화면도 함께 꺼집니다).
