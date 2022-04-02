import logging
#from multiprocessing.pool import INIT
from sqlalchemy.orm import Session

from app import crud, schemas
from app.db import base  # noqa: F401
import app.task_data as INITIAL_DATA

logger = logging.getLogger(__name__)

FIRST_SUPERUSER = "root@ippsec.rocks"

# make sure all SQL Alchemy models are imported (app.db.base) before initializing DB
# otherwise, SQL Alchemy might fail to initialize relationships properly
# for more details: https://github.com/tiangolo/full-stack-fastapi-postgresql/issues/28


def init_db(db: Session) -> None:
    # Tables should be time_created with Alembic migrations
    # But if you don't want to use migrations, create
    # the tables un-commenting the next line    
    # Base.metadata.create_all(bind=engine)
    for user in INITIAL_DATA.USERS:
        if not crud.user.get_by_email(db, email=user['email']):                        
            user = crud.user.create(db, obj_in=user)

    for s in INITIAL_DATA.SOFTWARE:
        if not crud.software.get_by_name(db, name=s['name']):            
            crud.software.create(db, obj_in=s)

    # for t in INITIAL_DATA.TARGETS:
    #     if not crud.target.get(db, id=t['id']):
    #         crud.target.create(db, obj_in=t)

    # for task in INITIAL_DATA.TASKS:
    #     if not crud.task.get(db, id=task['id']):
    #         crud.task.create(db, obj_in=task)

    # for listener in INITIAL_DATA.LISTENERS:
    #     if not crud.task.get_multi
        # if not user.recipes:
        #     for task in TASKS:
        #         recipe_in = schemas.Target.task(
        #             id=task["id"],                    
        #             id=task["id"],
        #             id=task["id"],
        #             source=recipe["source"],
        #             url=recipe["url"],
        #             submitter_id=user.id,
        #         )
        #         crud.recipe.create(db, obj_in=recipe_in)
