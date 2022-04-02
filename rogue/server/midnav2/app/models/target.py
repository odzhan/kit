from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from app.db.base_class import Base

class Software(Base):
    id = Column(Integer, primary_key=True, index=True)
    guid = Column(String, index=False)
    softwaretype = Column(Integer, nullable=False)
    name = Column(String(256), index=True, nullable=True)
    time_created = Column(Integer, index=False, nullable=True)
    description = Column(String(256), index=True, nullable=False)
    last_access = Column(Integer, index=False, nullable=True)
    last_update = Column(Integer, index=False, nullable=True)
    targets = relationship(
        "Target",
        back_populates="software"
    )


class Target(Base):

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    id = Column(Integer, primary_key=True, index=True)
    guid = Column(String, index=False)
    implant_id = Column(String, index=False, default="None")
    parent = Column(Integer, nullable=True, default=-1)
    software_id = Column(Integer, ForeignKey('software.id'), nullable=False)
    interval = Column(Integer, index=False, nullable=True, default=-1)
    os_version = Column(String(256), index=False, nullable=False)
    machine_name = Column(String(256), index=False, nullable=False)
    architecture = Column(String(256), index=False, nullable=False, default="x64")
    source_address = Column(String(256), index=False, nullable=False)
    wan_address = Column(String(256), index=False, nullable=True, default="0.0.0.0")
    parent = Column(String(256), index=False, nullable=True, default="None")
    time_created = Column(Integer, index=False, nullable=True, default=-1)
    time_lastcheckin = Column(Integer, index=False, nullable=True, default=-1)
    time_lastassignment = Column(Integer, index=False, nullable=True, default=-1)
    software = relationship(
        "Software",
        back_populates="targets"
    )
    tasks = relationship(
        "Task",
        back_populates="target"
    )
