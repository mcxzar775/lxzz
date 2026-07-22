from fastapi import APIRouter

from app.api.routes import admin, auth, connections, dashboard, nodes, users


api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(nodes.router)
api_router.include_router(connections.router)
api_router.include_router(users.router)
api_router.include_router(admin.router)
