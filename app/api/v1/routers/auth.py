from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from app.schemas.auth import RegisterRequest, LoginRequest
from app.schemas.token import TokenResponse
from app.schemas.user import UserResponse
from app.core.authentication.hashing import hash_password, verify_password
from app.core.authentication.auth_token import create_access_token
from app.core.storage import user_storage

router = APIRouter()


@router.post("/register", response_model=dict)
async def register(user_data: RegisterRequest):
    existing_user = user_storage.find_by_email(user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    existing_username = user_storage.find_by_username(user_data.username)
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    hashed_password = hash_password(user_data.password)
    user_dict = {
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hashed_password,
        "is_active": True
    }
    
    user_id = user_storage.create(user_dict)
    return {"message": "User created successfully", "user_id": user_id}


@router.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = user_storage.find_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )
    
    access_token = create_access_token(user["id"])
    return TokenResponse(access_token=access_token)