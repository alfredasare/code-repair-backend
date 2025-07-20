from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class SettingsCreate(BaseModel):
    model_id: str = Field(..., description="The model ID for settings")
    pattern_id: str = Field(..., description="The pattern ID for settings")
    retrievalK: int = Field(..., description="The retrieval K value for settings")


class SettingsUpdate(BaseModel):
    model_id: Optional[str] = Field(None, description="The model ID for settings")
    pattern_id: Optional[str] = Field(None, description="The pattern ID for settings")
    retrievalK: Optional[int] = Field(None, description="The retrieval K value for settings")


class SettingsResponse(BaseModel):
    id: str
    user_id: str
    model_id: str
    pattern_id: str
    retrievalK: int
    date_created: datetime
    date_modified: datetime