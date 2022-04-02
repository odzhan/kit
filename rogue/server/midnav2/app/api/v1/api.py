from fastapi import APIRouter

from app.api.v1.endpoints import user, task, websocket, target, testing, software


api_router = APIRouter()
api_router.include_router(user.router, prefix="/user", tags=["user"])
api_router.include_router(software.router, prefix="/software", tags=["software"])
api_router.include_router(target.router, prefix="/target", tags=["target"])
api_router.include_router(task.router, prefix="/task", tags=["task"])
api_router.include_router(websocket.router, prefix="/ws", tags=["ws"])
api_router.include_router(testing.router, prefix="/testing", tags=["testing"])

