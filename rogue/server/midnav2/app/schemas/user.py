from pydantic import BaseModel, HttpUrl, EmailStr

from typing import Sequence, Optional


class UserBase(BaseModel):
    """
    Utilized for authentication. Roles:
    -> Listener
    -> Operator
    -> Administrator
    """
    guid: Optional[str]
    first_name: Optional[str]
    surname: Optional[str]
    email: Optional[EmailStr] = None
    role: int
    date: int
    time_created: Optional[int]
    is_superuser: bool = False


# Properties to receive via API on creation
class UserCreate(UserBase):
    email: EmailStr
    password: str
    time_created: Optional[int]



# Properties to receive via API on update
class UserUpdate(UserBase):
    ...



class UserInDBBase(UserBase):
    id: Optional[int] = None

    class Config:
        orm_mode = True


# Additional properties stored in DB but not returned by API
class UserInDB(UserInDBBase):
    hashed_password: str


# Additional properties to return via API
class User(UserInDBBase):
    ...
