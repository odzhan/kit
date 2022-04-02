from pydantic import BaseModel, HttpUrl

from typing import Sequence, Optional

    
class TargetBase(BaseModel):
    id: Optional[int]
    guid: Optional[str]
    implant_id: Optional[str]
    time_created: Optional[int]
    time_lastcheckin: Optional[int]
    time_lastassignment: Optional[int]
 

class TargetCreate(TargetBase):
    software_id: int
    parent: Optional[str]
    interval: Optional[int]
    implant_id: Optional[str]
    os_version: str
    machine_name: str
    architecture: str
    source_address: str
    wan_address: Optional[str]
    time_created: Optional[int]
    time_lastcheckin: Optional[int]
    time_lastassignment: Optional[int]



class TargetUpdate(TargetBase):
    interval: Optional[int]    
    time_lastassignment: int


class TargetAll(TargetBase):
    id: int
    guid: Optional[str]
    implant_id: Optional[str]
    software_id: Optional[int]
    parent: Optional[str]
    os_version: Optional[str]
    machine_name: Optional[str]
    architecture: Optional[str]
    source_address: Optional[str]
    wan_address: Optional[str]    
    interval: Optional[int]
    time_created: Optional[int]
    time_lastcheckin: Optional[int]
    time_lastassignment: Optional[int]


    class Config:
        orm_mode = True



class TargetInDBBase(TargetBase):
    id: Optional[int] = None
    interval: Optional[int] = None

    class Config:
        orm_mode = True


# Additional properties to return via API
class Target(TargetInDBBase):
    pass


class TargetSearchResults(BaseModel):
    results: Sequence[TargetAll]
    

class SoftwareBase(BaseModel):
    id: int
    time_created: Optional[int]
    guid: str
    softwaretype: int


class SoftwareCreate(SoftwareBase):
    name: str
    description: str
    time_created: Optional[int]
    

class SoftwareUpdate(SoftwareBase):
    name: str
    description: str


class SoftwareInDBBase(SoftwareBase):
    id: Optional[int] = None

    class Config:
        orm_mode = True

class SoftwareAll(SoftwareBase):
    id: int
    name: str
    time_created: Optional[int]
    guid: str
    description: str
    softwaretype: int

    class Config:
        orm_mode = True

# Additional properties to return via API
class Software(SoftwareInDBBase):
    pass


class SoftwareSearchResults(BaseModel):
    results: Sequence[SoftwareAll]
