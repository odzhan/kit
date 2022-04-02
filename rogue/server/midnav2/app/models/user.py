from sqlalchemy import Integer, String, Column, Boolean
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class User(Base):

   #  def as_dict(self):
   #     return {c.name: getattr(self, c.name) for c in self.__table__.columns}
      
   id = Column(Integer, primary_key=True, index=True)
   guid = Column(String, index=False)
   first_name = Column(String(256), nullable=True)
   surname = Column(String(256), nullable=True)
   email = Column(String, index=True, nullable=False)
   role = Column(Integer, default=1)
   date = Column(Integer, nullable=False)
   time_created = Column(Integer, nullable=True)
   is_superuser = Column(Boolean, default=False)
   hashed_password = Column(String, nullable=False)
   last_update = Column(Integer, index=False, nullable=True)
   tasks = relationship(
        "Task",
        back_populates="submitter"
    )
