from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    pattern_id: str = Field(..., description="The pattern ID to use for querying")
    cwe_id: str = Field(..., description="The CWE identifier")
    cve_id: str = Field(..., description="The CVE identifier")
    additional_params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional pattern-specific parameters")


class QueryResponse(BaseModel):
    pattern_id: str
    results: Dict[str, Any]
    message: str = "Query executed successfully"