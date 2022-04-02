from typing import Any, Dict, Optional, Union
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.target import Target
from app.models.target import Software


from app.schemas.target import TargetCreate, TargetUpdate
from app.schemas.target import SoftwareCreate, SoftwareUpdate


class CRUDTarget(CRUDBase[Target, TargetCreate, TargetUpdate]):
    def get_by_owner(self, db: Session, *, parent: int) -> Optional[Target]:
        return db.query(Target).filter(Target.parent == parent)

class CRUDSoftware(CRUDBase[Software, SoftwareCreate, SoftwareUpdate]):
    def get_by_name(self, db: Session, *, name: str) -> Optional[Software]:
        return db.query(Software).filter(Software.name == name).first()


target = CRUDTarget(Target)
software = CRUDSoftware(Software)
