from fastapi import APIRouter, Depends
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: UserResponse = Depends(get_current_user)):
    return current_user