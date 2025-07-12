from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class PatternCreate(BaseModel):
    name: str = Field(..., description="The name of the pattern")
    pattern_id: str = Field(..., description="The unique pattern identifier")
    description: str = Field(..., description="The pattern description")


class PatternUpdate(BaseModel):
    name: Optional[str] = Field(None, description="The name of the pattern")
    pattern_id: Optional[str] = Field(None, description="The unique pattern identifier")
    description: Optional[str] = Field(None, description="The pattern description")


class PatternResponse(BaseModel):
    id: str
    name: str
    pattern_id: str
    description: str
    date_created: datetime
    date_modified: datetime


class PatternListResponse(BaseModel):
    patterns: list[PatternResponse]
    total: int