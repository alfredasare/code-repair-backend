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
    vulnerable_code: str
    pattern_id: str
    cwe_id: str
    cve_id: str
    additional_params: Dict[str, Any]
    description: Optional[str]
    user_id: str
    date_created: datetime
    date_modified: datetime
    repair_recommendation: Optional[str] = None
    code_fix: Optional[str] = None
    evaluation_scores: Optional[Dict[str, Any]] = None


class AssessmentListResponse(BaseModel):
    assessments: List[AssessmentResponse]
    total: int


# Code Repair Recommendation Models
class CodeRepairRecommendationRequest(BaseModel):
    model_id: str = Field(..., description="The model ID to use for generation")
    vulnerable_code: str = Field(..., description="The vulnerable code to analyze")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    retrieved_context: str = Field(..., description="The context retrieved from pattern matching")


class CodeRepairRecommendationResponse(BaseModel):
    recommendation: str


# Code Fix Models
class CodeFixRequest(BaseModel):
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
    user_id: str = Field(..., description="The user ID")
    recommendation: str = Field(..., description="The repair recommendation")
    vulnerable_code: str = Field(..., description="The vulnerable code")
    model_id: str = Field(..., description="The model ID used for generation")


class StoreResultsResponse(BaseModel):
    assessment_id: str
    stored_fields: List[str]
    message: str
    stored_at: datetime