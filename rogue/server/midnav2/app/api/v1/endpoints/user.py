from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app import crud
from app import schemas
from app.api import deps
from app.models.user import User

from app.core.auth import (
    authenticate,
    create_access_token,
)

router = APIRouter()

@router.get("/{user_id}", status_code=200, response_model=schemas.User)
def fetch_user(*, 
    user_id: int, 
    db: Session = Depends(deps.get_db) 
    ) -> Any:
    """
    Fetch a user by ID
    """
    result = crud.user.get(db=db, id=user_id)
    return result


@router.post("/login")
def login(db: Session = Depends(deps.get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    Get the JWT for a user with data from OAuth2 request form body.
    """
    user = authenticate(email=form_data.username, password=form_data.password, db=db)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {
        "access_token": create_access_token(sub=user.id, role=user.role, is_superuser=user.is_superuser, guid=user.guid),
        "token_type": "bearer",
    }


@router.post("/signup", response_model=schemas.User, status_code=201)
def create_user_signup(
    *,
    db: Session = Depends(deps.get_db),
    user_in: schemas.user.UserCreate,
) -> Any:
    """
    Create new user without the need to be logged in.
    """
    if not user_in.guid:
        user_in.guid = str(uuid4())
    user = db.query(User).filter(User.email == user_in.email).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system",
        )
    user = crud.user.create(db=db, obj_in=user_in)

    return user