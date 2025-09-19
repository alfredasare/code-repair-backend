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
        
        # If this is a graph pattern, add D3 visualization data
        if "graph" in request.pattern_id and hasattr(handler, 'get_graph_data'):
            try:
                graph_data = handler.get_graph_data(
                    cwe_id=request.cwe_id,
                    cve_id=request.cve_id,
                    graph_data_source_id=graph_data_source_id,
                    **request.additional_params
                )
                results["graph_visualization"] = graph_data
            except Exception as e:
                print(f"Failed to generate graph data: {e}")
                results["graph_visualization_error"] = str(e)
        
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