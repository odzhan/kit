import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import crud
from app.api import deps
from app.schemas.task import Task, TaskCreate, TaskSearchResults
from app.websocket.notification import ws
from pydantic_sqlalchemy import sqlalchemy_to_pydantic


router = APIRouter()

@router.get("/task/{task_id}", status_code=200)
async def new_task(*, task_id: int, db: Session = Depends(deps.get_db) ) -> Any:
    """
    Manually notify the clients about a specific task.
    """
    task = crud.task.get(db=db, id=task_id)
    
    await ws.publish(["task"], data=task.as_dict() )