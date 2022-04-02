import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from typing import Any, Optional
from uuid import uuid4

from app import crud
from app.api import deps
from app.core.state import Role
from app.schemas.user import User
from app import schemas
from app.schemas.task import Task, TaskCreate, TaskSearchResults
from app.core.state import TaskStatus
from app.core.helpers import current_time_ms

from app.websocket.notification import ws

router = APIRouter()


@router.get("/", status_code=200, response_model=TaskSearchResults)
def get_tasks_active(*, 
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db) 
) -> Any:
    """
    Fetch Active tasks. If role is listener, only provides tasks owned by them. 
    ToDo: Will need to make parent recursive, for pivots.
    """
    if current_user["role"] == Role.Listener.value:
        # Tasks has a relationship to Target, grab tasks to the targets we are interested in.
        targets = crud.target.get_multi(db=db)
        listener = [target for target in targets if target.parent == current_user["guid"] ][0]
        # Grab all tasks owned by listener, flatten the list, and then filter out completed.
        tasks = [target.tasks for target in targets if target.parent == listener.guid ]
        tasks = [item for sublist in tasks for item in sublist]
        tasks = filter(lambda task: TaskStatus.Completed.value != task.status, tasks)
    else:
        tasks = crud.task.get_active(db=db)               
    
    # If no tasks.
    if not tasks:
        raise HTTPException(
            status_code=404, detail=f"No tasks in the database"
        )

    return {"results": list(tasks) }


@router.get("/all", status_code=200, response_model=TaskSearchResults)
def fetch_tasks_all(*, 
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db) 
) -> Any:
    """
    Fetch all tasks
    """
    if current_user["role"] == Role.Listener.value:
        # Tasks has a relationship to Target, grab tasks to the targets we are interested in.
        targets = crud.target.get_multi(db=db)
        listener = [target for target in targets if target.parent == current_user["guid"] ][0]
        # Grab all tasks owned by listener, flatten the list, and then filter out completed.
        tasks = [target.tasks for target in targets if target.parent == listener.guid ]
        tasks = [item for sublist in tasks for item in sublist]    
    else:
        tasks = crud.task.get_multi(db=db)
    
    # If no tasks.
    if not tasks:
        raise HTTPException(
            status_code=404, detail=f"No tasks in the database"
        )

    return {"results": list(tasks) }


@router.get("/{task_id}", status_code=200, response_model=TaskSearchResults)
async def get_task_by_id(*,
    task_id: int,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db) 
) -> Any:
    """
    Fetch a single task by ID
    """
    task = crud.task.get(db=db, id=task_id)

    if not task:
        raise HTTPException(
            status_code=404, detail=f"Task with ID {task_id} not found"
        )

    task = task.as_dict()
    return {"results" : list([ task ]) }


@router.put("/", status_code=200, response_model=TaskSearchResults)
async def update_task_by_id(*,
    task_in: schemas.task.TaskUpdate,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db) 
) -> Any:
    """
    Update a task
    """
    if task_in.id:
        task = crud.task.get(db=db, id=task_in.id)
    else:
        task = crud.task.get(db=db, id=task_in.guid)

    if not task:
        raise HTTPException(
            status_code=404, detail=f"Task not found"
        )
    
    # Update time variables in database
    if task_in.status == TaskStatus.Assigned.value:
        task_in.time_assigned = current_time_ms()
    if task_in.status == TaskStatus.Working.value:
        task_in.time_started = current_time_ms()
    elif task_in.status == TaskStatus.Completed.value:
        task_in.time_finished = current_time_ms()

    task = crud.task.update(db=db, db_obj=task, obj_in=task_in)

    await ws.publish(["tasks"], data=task.as_dict())
    results = []
    results.append(task.as_dict())

    return {"results" : results }



@router.get("/search/owner/{id}", status_code=200, response_model=TaskSearchResults)
def get_tasks_by_owner(
    *,
    owner: str = Query(None, min_length=3, example="root"),
    max_results: Optional[int] = 10,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db),
) -> dict:
    """
    Search for Tasks based on output
    """
    user = crud.user.get_multi(db=db, id=id)
    results = user.tasks            
    return {"results": list(results)[:max_results]}


@router.get("/search/parent/{id}", status_code=200, response_model=TaskSearchResults)
def get_tasks_by_parent(
    *,
    parent: str = Query(None, min_length=3, example="root"),
    max_results: Optional[int] = 10,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db),
) -> dict:
    """
    Search for Tasks based on output
    """
    tasks = crud.task.get_multi(db=db, parent=parent)

    return {"results": list(results)[:max_results]}


@router.get("/search/output/{search_str}", status_code=200, response_model=TaskSearchResults)
def get_tasks_by_output(
    *,
    search_str: Optional[str] = Query(None, min_length=3, example="root"),
    max_results: Optional[int] = 10,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db),
) -> dict:
    """
    Search for Tasks based on output
    """
    tasks = crud.task.get_multi(db=db, limit=max_results)
    if not search_str:
        return {"results": tasks}
    
    results = filter(lambda task: search_str.lower() in task.return_data.lower(), tasks)

    return {"results": list(results)[:max_results]}
    

@router.post("/", status_code=200, response_model=Task)
async def create_task(*, 
    task_in: schemas.task.TaskCreate,
    request: Request,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db) ) -> dict:
    """
    Create a task
    """
    task_in.guid = str(uuid4())
    task_in.status = 0
    task_in.time_created = current_time_ms()
    task_in.submitter_id = current_user["sub"]
    task = crud.task.create(db=db, obj_in=task_in)
    
    # # Merge Target and Task
    # output = task.target.as_dict()
    # task = task.as_dict()
    # output.update(task)

    await ws.publish(["tasks"], data=task.as_dict())

    return task
