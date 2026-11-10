from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["Authorization"],
)
