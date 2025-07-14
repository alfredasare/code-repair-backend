from fastapi import APIRouter, HTTPException, status, Depends
from datetime import datetime
from app.schemas.assessment import (
    AssessmentCreate, AssessmentUpdate, AssessmentResponse, AssessmentListResponse,
    CodeRepairRecommendationRequest, CodeRepairRecommendationResponse,
    CodeFixRequest, CodeFixResponse,
    EvaluationScoresRequest, EvaluationScoresResponse,
    StoreResultsRequest, StoreResultsResponse
)
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.prompts import get_repair_recommendation_prompt, get_code_fix_prompt
from app.core.llm import LLMFactory
from app.core.storage import assessment_storage
from app.core.evaluation import evaluate_recommendation

router = APIRouter()


# ─── CRUD ENDPOINTS ─────────────────────────────────────────────────────────────

@router.get("/", response_model=AssessmentListResponse)
async def list_assessments(current_user: UserResponse = Depends(get_current_user)):
    """List all assessments for the current user"""
    # TODO: Implement assessment listing logic
    pass


@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(assessment_id: str, current_user: UserResponse = Depends(get_current_user)):
    """Get a specific assessment by ID"""
    # TODO: Implement get assessment logic
    pass


@router.post("/", response_model=AssessmentResponse)
async def create_assessment(
    assessment_data: AssessmentCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    """Create a new assessment"""
    # TODO: Implement assessment creation logic
    pass


@router.put("/{assessment_id}", response_model=AssessmentResponse)
async def update_assessment(
    assessment_id: str,
    assessment_data: AssessmentUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    """Update an existing assessment"""
    # TODO: Implement assessment update logic
    pass


@router.delete("/{assessment_id}")
async def delete_assessment(assessment_id: str, current_user: UserResponse = Depends(get_current_user)):
    """Delete an assessment"""
    # TODO: Implement assessment deletion logic
    pass


# ─── MAIN ASSESSMENT ENDPOINTS ─────────────────────────────────────────────────

@router.post("/generate-recommendation", response_model=CodeRepairRecommendationResponse)
async def generate_code_repair_recommendation(
    request: CodeRepairRecommendationRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    """Generate a code repair recommendation for an assessment"""
    try:
        # Get the LLM instance
        llm = LLMFactory.create_llm(model_type=request.model_type, model_id=request.model_id)
        
        # Prepare the prompt with request data
        prompt = get_repair_recommendation_prompt(
            cwe_id=request.cwe_id, 
            cve_id=request.cve_id, 
            retrieved_context=request.retrieved_context, 
            vulnerable_code=request.vulnerable_code
        )
        
        # Generate the recommendation using LLM
        result = llm.invoke(prompt)
        
        # Extract recommendation text from result
        recommendation = result.content if hasattr(result, 'content') else str(result)
        
        return CodeRepairRecommendationResponse(
            recommendation=recommendation
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate code repair recommendation: {str(e)}"
        )


@router.post("/generate-fix", response_model=CodeFixResponse)
async def generate_code_fix(
    request: CodeFixRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    """Generate a code fix for an assessment"""
    try:
        # Get the LLM instance
        llm = LLMFactory.create_llm(model_type=request.model_type, model_id=request.model_id)
        
        # Prepare the prompt with request data
        prompt = get_code_fix_prompt(
            cwe_id=request.cwe_id, 
            cve_id=request.cve_id, 
            vulnerable_code=request.vulnerable_code, 
            recommendation=request.recommendation
        )
        
        # Generate the fix using LLM
        result = llm.invoke(prompt)
        
        # Extract fixed code from result
        fixed_code = result.content if hasattr(result, 'content') else str(result)
        
        return CodeFixResponse(
            fixed_code=fixed_code
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate code fix: {str(e)}"
        )


@router.post("/evaluate", response_model=EvaluationScoresResponse)
async def evaluate_code_fix(
    request: EvaluationScoresRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    """Evaluate a code fix based on predefined criteria"""
    try:
        import asyncio
        import concurrent.futures
        
        # Run evaluation in a thread pool to avoid event loop conflicts
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            scores = await loop.run_in_executor(
                executor,
                evaluate_recommendation,
                request.vulnerable_code,
                request.cwe_id,
                request.cve_id,
                request.recommendation,
                request.retrieved_context,
                request.model
            )
        
        return EvaluationScoresResponse(
            recommendation=request.recommendation,
            vulnerable_code=request.vulnerable_code,
            cve_id=request.cve_id,
            cwe_id=request.cwe_id,
            scores=scores
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to evaluate code fix: {str(e)}"
        )


@router.post("/store-results", response_model=StoreResultsResponse)
async def store_assessment_results(
    request: StoreResultsRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    """Store all assessment results (recommendation, fix, scores)"""
    try:
        # Create assessment data
        assessment_data = {
            "user_id": current_user.id,
            "vulnerable_code": request.vulnerable_code,
            "repair_recommendation": request.recommendation,
            "model_id": request.model_id,
            "evaluation_scores": request.scores,
        }
        
        # Store in MongoDB
        assessment_id = assessment_storage.create(assessment_data)
        
        # Prepare stored fields list
        stored_fields = ["user_id", "vulnerable_code", "repair_recommendation", "model_id", "evaluation_scores"]
        
        return StoreResultsResponse(
            assessment_id=assessment_id,
            stored_fields=stored_fields,
            message="Assessment results stored successfully",
            stored_at=datetime.utcnow()
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store assessment results: {str(e)}"
        )