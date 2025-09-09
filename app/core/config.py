from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    mongodb_uri: str = Field(default="mongodb://localhost:27017/auth_db")
    database_name: str = Field(default="auth_db")
    secret_key: str = Field(default="your-secret-key-here")
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    neo4j_uri: str = Field(default="neo4j://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="password")
    openai_api_key: str = Field(default="sk-proj-1234567890")
    groq_api_key: str = Field(default="grk_1234567890")
    pinecone_api_key: str = Field(default="pcsk_1234567890")
    credential_encryption_key: str = Field(default="")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()