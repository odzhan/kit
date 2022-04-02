import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Optional

from app import crud
from app.api import deps

from app import schemas

from app.schemas.user import User
from app.models.target import Target
from app.core.state import Role, SoftwareType
from app.core.helpers import current_time_ms

from app.websocket.notification import ws

router = APIRouter()


@router.get("/", status_code=200, response_model=schemas.target.TargetSearchResults)
def get_targets(
    *, 
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Fetch targets. If role is listener, only provides targets owned by them. 
    ToDo: Will need to make parent recursive, for pivots.
    """
    # Listeners should only see targets they control.
    if current_user["role"] == Role.Listener.value:
        listeners = crud.target.get_by_owner(db=db, parent=current_user["guid"])
        targets = []
        # ToDo: Need to do some fancy graph here so we can get multiple levels.
        for listener in listeners:
            implants = crud.target.get_by_owner(db=db, parent=listener.guid)
            targets += implants                    
    # If not a listener, return every target
    else:        
        targets = crud.target.get_multi(db=db)

    return {"results": list(targets) }


@router.post("/", status_code=200, response_model=schemas.target.Target)
async def new_target(
    target_in: schemas.target.TargetCreate,
    request: Request,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Create a new target
    """
    # If no parent, assign beacon to user
    if not target_in.parent:
        target_in.parent = current_user["guid"]
    # if no wan address, set based upon the request
    if not target_in.wan_address:
        target_in.wan_address = request.client.host

    # Set Timestamps
    target_in.time_lastcheckin = current_time_ms()
    target_in.time_lastassignment = current_time_ms()

    target = crud.target.create(db=db, obj_in=target_in)

    await ws.publish(["targets"], data=target.as_dict())
    
    return target


@router.put("/", status_code=200, response_model=schemas.target.Target)
def update_target(
    target_in: schemas.target.TargetUpdate,
    request: Request,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Update a target
    """
    # ToDo
    return None


@router.delete("/{target_id}", status_code=200)
def remove_target(
    target_id: int,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Delete a target
    """
    crud.target.remove(db=db, id=target_id)
    return True
