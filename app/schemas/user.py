from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    date_created: datetime
    date_modified: datetime