from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    mongodb_uri: str = Field(default="mongodb://localhost:27017/auth_db")
    database_name: str = Field(default="auth_db")
    secret_key: str = Field(default="your-secret-key-here")
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()