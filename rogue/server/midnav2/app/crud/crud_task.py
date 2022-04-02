from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.crud.base import CRUDBase

from app.models.task import Task
from app.core.state import TaskStatus
from app.schemas.task import TaskCreate, TaskUpdate


class CRUDTask(CRUDBase[Task, TaskCreate, TaskUpdate]):
    def get_by_output(self, db: Session, output: str) -> Optional[Task]:
        results = db.query(Task).filter(Task.return_data.like(output))
        return results

    def get_active(self, db: Session) -> Optional[Task]:
        """
        Get a list of tasks filtered by owner.
        """
        return db.query(Task).filter(Task.status != TaskStatus.Completed.value)

    def get_by_listener(self, db: Session, listener: int) -> Optional[Task]:
        """
        Get a list of tasks filtered by owner.
        """
        return db.query(Task).filter(Task.target_id == listener)

task = CRUDTask(Task)
