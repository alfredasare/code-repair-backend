from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class CriteriaCreate(BaseModel):
    name: str = Field(..., description="The name of the criteria")
    criteria: str = Field(..., description="The evaluation criteria description")
    evaluation_steps: List[str] = Field(..., description="List of evaluation steps")


class CriteriaUpdate(BaseModel):
    name: Optional[str] = Field(None, description="The name of the criteria")
    criteria: Optional[str] = Field(None, description="The evaluation criteria description")
    evaluation_steps: Optional[List[str]] = Field(None, description="List of evaluation steps")


class CriteriaResponse(BaseModel):
    id: str
    name: str
    criteria: str
    evaluation_steps: List[str]
    date_created: datetime
    date_modified: datetime


class CriteriaListResponse(BaseModel):
    criteria: List[CriteriaResponse]
    total: int