# FastAPI: CORS 허용 도메인을 직접 적기

쿠키가 필요하면 `allow_origins`에 실제 도메인 목록을 넣습니다. 목록은 환경 변수에서 읽으면 배포 환경마다 바꾸기 쉽습니다.

```python
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# 예: CORS_ORIGINS="https://app.example.com,https://admin.example.com"
origins = [o.strip() for o in os.environ["CORS_ORIGINS"].split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,          # "*" 대신 실제 도메인만
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # 필요한 것만
    allow_headers=["Authorization", "Content-Type"],
)
```

쿠키 인증을 쓰지 않는 공개 API라면 `allow_credentials=False`로 바꾸면 `allow_origins=["*"]`를 그대로 써도 됩니다.

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
)
```
