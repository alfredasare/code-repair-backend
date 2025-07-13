from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.query import QueryRequest, QueryResponse
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.patterns.factory import QueryHandlerFactory

router = APIRouter()


@router.post("/", response_model=QueryResponse)
async def query_pattern(
    request: QueryRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    try:
        handler = QueryHandlerFactory.get_handler(request.pattern_id)
        results = handler.execute_query(
            cwe_id=request.cwe_id,
            cve_id=request.cve_id,
            **request.additional_params
        )
        
        return QueryResponse(
            pattern_id=request.pattern_id,
            results=results or {},
            message="Query executed successfully"
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query execution failed: {str(e)}"
        )