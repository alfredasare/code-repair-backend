from datetime import datetime, timedelta
from typing import Optional
import jwt
from app.core.config import settings


def create_access_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "user_id": user_id,
        "exp": expire
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
    return token


def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("user_id")
        if user_id is None:
            return None
        return user_id
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None