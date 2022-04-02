import asyncio

from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse

from typing import Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session

from app.schemas.target import Target 
from app.schemas.task import Task, TaskSearchResults
from app.schemas.user import User
from app.api.v1.api import api_router
from app.core.config import settings

from app import deps
from app import crud
from app.websocket import notification



app = FastAPI(title="Midna V2", openapi_url="/openapi.json")
root_router = APIRouter(default_response_class=UJSONResponse)

# Init endpoint
(notification.ws).register_route(root_router, path="/midna")

@api_router.get("/", status_code=200)
def root():
    """
    Root GET
    """
    return {"msg": "Hello, World!"}


app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(root_router)

def start():
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")

if __name__ == "__main__":
    # Use this for debugging purposes only
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")
