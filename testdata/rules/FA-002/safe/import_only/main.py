from fastapi import FastAPI, APIRouter

router = APIRouter()


@router.get("/ping")
def ping() -> dict:
    return {"ok": True}


def mount(app: FastAPI) -> None:
    app.include_router(router)
