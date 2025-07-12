from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class ModelType(str, Enum):
    openai = "openai"
    groq = "groq"


class ModelCreate(BaseModel):
    name: str = Field(..., description="The name of the model")
    model_id: str = Field(..., description="The unique model identifier")
    type: ModelType = Field(..., description="The type of the model (openai or groq)")


class ModelUpdate(BaseModel):
    name: Optional[str] = Field(None, description="The name of the model")
    model_id: Optional[str] = Field(None, description="The unique model identifier")
    type: Optional[ModelType] = Field(None, description="The type of the model (openai or groq)")


class ModelResponse(BaseModel):
    id: str
    name: str
    model_id: str
    type: ModelType
    date_created: datetime
    date_modified: datetime


class ModelListResponse(BaseModel):
    models: list[ModelResponse]
    total: int