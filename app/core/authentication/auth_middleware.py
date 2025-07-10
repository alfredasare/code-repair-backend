from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.core.authentication.auth_token import decode_token
from app.core.storage import user_storage
from app.schemas.user import UserResponse

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserResponse:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    user_id = decode_token(token)
    if user_id is None:
        raise credentials_exception
    
    user = user_storage.find_by_id(user_id)
    if user is None:
        raise credentials_exception
    
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    
    return UserResponse(**user)