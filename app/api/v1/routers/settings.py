from fastapi import APIRouter
from app.api.v1.routers import criteria

router = APIRouter()

router.include_router(criteria.router, prefix="/criteria", tags=["criteria"])