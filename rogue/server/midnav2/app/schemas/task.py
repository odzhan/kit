from pydantic import BaseModel, HttpUrl
import orjson
import json
from typing import Sequence, Optional, List, Union, Dict

def write_list_item(item):
    return [item.a, item.b]

def orjson_dumps(v, *, default):
    # orjson.dumps returns bytes, to match standard json.dumps we need to decode
    return orjson.dumps(v, default=default).decode()

class args(BaseModel):
    cmd: Optional[str]
    sleep: Optional[str]
    seconds: Optional[str]
    pid: Optional[str]
    dll: Optional[str]


class TaskBase(BaseModel):
    id: Optional[int]
    target_id: Optional[int]
    guid: Optional[str]
    code: Optional[int]
    submitter_id: Optional[int]
    args: Optional[Dict]
    status: Optional[int]    
    return_data: Optional[str]
    return_code: Optional[int]
    time_created: Optional[int]
    time_assigned: Optional[int]
    time_started: Optional[int]
    time_finished: Optional[int]

    class Config:
        json_loads = orjson.loads
        json_dumps = orjson_dumps
        json_encoders = {args: write_list_item}
        orm_mode = True


class TaskCreate(TaskBase):
    target_id: Optional[int]
    code: Optional[int]
    args: Dict

    
class TaskUpdate(TaskBase):
    status: Optional[int]
    return_data: Optional[str]
    return_code: Optional[int]


# Properties shared by models stored in DB
class TaskInDBBase(TaskBase):
    id: int
    submitter_id: int
    target_id: int

    class Config:
        orm_mode = True
        json_encoders = {args: write_list_item}



# Properties to return to client
class Task(TaskInDBBase):
    pass




# Properties properties stored in DB
class TaskInDB(TaskInDBBase):
    pass


class TaskSearchResults(BaseModel):
    results: Sequence[Task]
