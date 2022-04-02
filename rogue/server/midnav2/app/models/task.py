from sqlalchemy import Integer, String, Column, Boolean, ForeignKey, Text
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import relationship
import json
from app.db.base_class import Base

class TextPickleType(TypeDecorator):
    impl = Text(256)

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value

class Task(Base):
    
   def as_dict(self):
      return {c.name: getattr(self, c.name) for c in self.__table__.columns}

   def __iter__(self):
      return {c.name: getattr(self, c.name) for c in self.__table__.columns}

   id = Column(Integer, primary_key=True, index=True)
   guid = Column(String, index=False)
   submitter_id =  Column(Integer, ForeignKey("user.id"), nullable=False)
   target_id = Column(Integer, ForeignKey("target.id"), nullable=True)   
   code =  Column(Integer, nullable=False)
   args = Column(TextPickleType(), index=False, nullable=True)
   status = Column(Integer, index=False, nullable=False)
   # Need Argument
   return_data = Column(String, index=False, nullable=True, default="")
   return_code = Column(Integer, index=False, nullable=True, default=-1)
   time_created = Column(Integer, nullable=False, default=-1)
   time_assigned = Column(Integer, nullable=False, default=-1)
   time_started = Column(Integer, index=False, nullable=True, default=-1) #Unix epoch timestamp, milliseconds
   time_finished = Column(Integer, index=False, nullable=True, default=-1)
   submitter = relationship(
      "User",
      back_populates="tasks"
   )
   target =  relationship(
      "Target", 
      back_populates="tasks"
   )
