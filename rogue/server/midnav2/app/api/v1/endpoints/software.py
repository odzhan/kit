import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import crud
from app.api import deps

from app import schemas

from app.schemas.user import User
from app.models.target import Software
from app.core.state import Role, SoftwareType

from app.websocket.notification import ws

router = APIRouter()


@router.get("/", status_code=200, response_model=schemas.target.SoftwareSearchResults)
def get_software(
    *, 
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Output all software
    """
    software = crud.software.get_multi(db=db)

    return {"results": list(software) }