from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.query import QueryRequest, QueryResponse
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.patterns.factory import QueryHandlerFactory
from app.core.storage import settings_storage

router = APIRouter()


@router.post("/", response_model=QueryResponse)
async def query_pattern(
    request: QueryRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    try:
        # Get user settings to determine data source preferences
        user_settings = settings_storage.find_by_user_id(current_user.id)
        
        vector_data_source_id = None
        graph_data_source_id = None
        
        if user_settings:
            vector_data_source_id = user_settings.get("vector_data_source_id")
            graph_data_source_id = user_settings.get("graph_data_source_id")
        
        # Validate data source compatibility with pattern
        QueryHandlerFactory.validate_data_source_compatibility(
            request.pattern_id,
            vector_data_source_id,
            graph_data_source_id
        )
        
        handler = QueryHandlerFactory.get_handler(request.pattern_id)
        results = handler.execute_query(
            cwe_id=request.cwe_id,
            cve_id=request.cve_id,
            vector_data_source_id=vector_data_source_id,
            graph_data_source_id=graph_data_source_id,
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