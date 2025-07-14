from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


# Base Assessment Models
class AssessmentCreate(BaseModel):
    vulnerable_code: str = Field(..., description="The vulnerable code to assess")
    pattern_id: str = Field(..., description="The pattern ID to use for assessment")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    additional_params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional pattern-specific parameters")
    description: Optional[str] = Field(None, description="Optional description of the assessment")


class AssessmentUpdate(BaseModel):
    vulnerable_code: Optional[str] = Field(None, description="The vulnerable code to assess")
    pattern_id: Optional[str] = Field(None, description="The pattern ID to use for assessment")
    description: Optional[str] = Field(None, description="Optional description of the assessment")
    additional_params: Optional[Dict[str, Any]] = Field(None, description="Additional pattern-specific parameters")


class AssessmentResponse(BaseModel):
    id: str
    user_id: str
    evaluation_scores: Dict[str, Any] = Field(..., description="The evaluation scores to store")
    recommendation: str = Field(..., description="The repair recommendation")
    vulnerable_code: str = Field(..., description="The vulnerable code")
    fixed_code: str = Field(..., description="The fixed code")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    model_id: str = Field(..., description="The model ID used for generation")
    date_created: datetime = Field(..., description="The date the assessment was created")
    date_modified: datetime = Field(..., description="The date the assessment was last modified")


class AssessmentListResponse(BaseModel):
    assessments: List[AssessmentResponse]
    total: int


# Code Repair Recommendation Models
class CodeRepairRecommendationRequest(BaseModel):
    model_type: str = Field(default="openai", description="The model type to use for generation")
    model_id: str = Field(..., description="The model ID to use for generation")
    vulnerable_code: str = Field(..., description="The vulnerable code to analyze")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    retrieved_context: str = Field(..., description="The context retrieved from pattern matching")


class CodeRepairRecommendationResponse(BaseModel):
    recommendation: str


# Code Fix Models
class CodeFixRequest(BaseModel):
    model_type: str = Field(default="openai", description="The model type to use for generation")
    model_id: str = Field(..., description="The model ID to use for generation")
    vulnerable_code: str = Field(..., description="The vulnerable code to fix")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    recommendation: str = Field(..., description="The repair recommendation to base fix on")


class CodeFixResponse(BaseModel):
    fixed_code: str


# Evaluation Scores Models
class EvaluationScoresRequest(BaseModel):
    vulnerable_code: str = Field(..., description="The vulnerable code")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    recommendation: str = Field(..., description="The recommendation to evaluate")
    retrieved_context: str = Field(..., description="The context retrieved from pattern matching")
    model: str = Field(default="gpt-4o-mini", description="The model to use for evaluation")


class EvaluationScore(BaseModel):
    criterion: str
    score: float


class EvaluationScoresResponse(BaseModel):
    recommendation: str
    vulnerable_code: str
    cve_id: str
    cwe_id: str
    scores: Dict[str, float]


# Store Results Models
class StoreResultsRequest(BaseModel):
    scores: Dict[str, Any] = Field(..., description="The evaluation scores to store")
    recommendation: str = Field(..., description="The repair recommendation")
    vulnerable_code: str = Field(..., description="The vulnerable code")
    fixed_code: str = Field(..., description="The fixed code")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    model_id: str = Field(..., description="The model ID used for generation")


class StoreResultsResponse(BaseModel):
    assessment_id: str
    stored_fields: List[str]
    message: str
    stored_at: datetime