import asyncio
import httpx
import json
import random

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Optional
from random_word import RandomWords


from app import crud
from app.api import deps

from app import schemas

from app.schemas.user import User
from app.models.target import Target
from app.core.state import Role, SoftwareType

from app.websocket.notification import ws

router = APIRouter()

def get_auth() -> None:
    with httpx.Client() as client:
        data = { "username":"listener@midna.local", "password":"password"}
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        r = client.post(
            'http://127.0.0.1:8001/api/v1/user/login', data=data, headers=headers)
        token = json.loads(r.text)['access_token']
    return token


@router.get("/new_implant", status_code=200)
def new_implant(
    *, 
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Create a fake implant, tied to a random listener.    
    """
    words = RandomWords()
    token = get_auth()
    targets = crud.target.get_multi(db=db)
    # If we don't have any listeners... Get One.
    if len(targets) == 0:
        with httpx.Client() as client:
            headers = { 
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json' }
            body =   {
                "software_id": 1,
                "os_version": "Ubuntu",
                "machine_name": words.get_random_word(),
                "architecture": 1,
                "source_address": "127.0.0.1"
            }
            x = client.post("http://127.0.0.1:8001/api/v1/target/", json=body, headers=headers)

            targets = crud.target.get_multi(db=db)

    listeners = list(filter(lambda target: 2 == target.software_id, targets))
    rnd = len(listeners) - 1
    listener = listeners[rnd]

    with httpx.Client() as client:
        headers = { 
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json' }
        body =   {
            "parent": listener.guid,
            "software_id": 4,
            "os_version": "Windows",
            "interval": 30,
            "machine_name": words.get_random_word(),
            "architecture": 1,
            "source_address": "127.0.0.1"
        }
        x = client.post("http://127.0.0.1:8001/api/v1/target/", json=body, headers=headers)
    

    return x.text


@router.get("/new_task", status_code=200)
def new_task(
    *, 
    db: Session = Depends(deps.get_db)
) -> dict:
    """
    Create a fake task.
    """
    token = get_auth()
    targets = crud.target.get_multi(db=db)
    LongClaws = list(filter(lambda target: 4 == target.software_id, targets))
    rnd = len(LongClaws) - 1
    implant = LongClaws[rnd]

    with httpx.Client() as client:
        headers = { 
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json' }
        body =   {
            "target_id": implant.id,
            "code": 7,
            "args": {"command": "whoami"}
        }
        x = client.post("http://127.0.0.1:8001/api/v1/task/", json=body, headers=headers)
    

    return x.text
