from typing import List
from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.data_source import (
    DataSourceCreate, 
    DataSourceUpdate, 
    DataSourceResponse, 
    DataSourceListResponse,
    DataSourceTestResponse
)
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.storage import data_source_storage
from app.core.connections.encryption import credential_encryption
from app.core.connections.manager import connection_manager

router = APIRouter()


@router.post("/", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_data_source(
    request: DataSourceCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    """Create a new data source configuration"""
    try:
        # Encrypt credentials before storing
        encrypted_credentials = credential_encryption.encrypt_credentials(request.credentials)
        
        # If this is set as default, unset any existing defaults of the same type
        if request.is_default:
            existing_defaults = data_source_storage.find_by_type(request.db_type)
            for existing in existing_defaults:
                if existing.get("is_default", False):
                    data_source_storage.update_by_id(existing["id"], {"is_default": False})
        
        # Create the data source record
        data_source_data = {
            "name": request.name,
            "db_type": request.db_type,
            "provider": request.provider,
            "credentials": encrypted_credentials,
            "connection_params": request.connection_params,
            "is_default": request.is_default,
            "is_active": request.is_active,
            "created_by": current_user.id
        }
        
        data_source_id = data_source_storage.create(data_source_data)
        created_data_source = data_source_storage.find_by_id(data_source_id)
        
        if not created_data_source:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve created data source"
            )
        
        return DataSourceResponse(
            id=created_data_source["id"],
            name=created_data_source["name"],
            db_type=created_data_source["db_type"],
            provider=created_data_source["provider"],
            connection_params=created_data_source["connection_params"],
            is_default=created_data_source["is_default"],
            is_active=created_data_source["is_active"],
            date_created=created_data_source["date_created"],
            date_modified=created_data_source["date_modified"]
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create data source: {str(e)}"
        )


@router.get("/", response_model=List[DataSourceListResponse])
async def list_data_sources(
    current_user: UserResponse = Depends(get_current_user),
    db_type: str = None,
    active_only: bool = True
):
    """List all data source configurations"""
    try:
        if db_type:
            if active_only:
                data_sources = data_source_storage.find_by_type(db_type)
            else:
                data_sources = data_source_storage.find_many({"db_type": db_type})
        else:
            if active_only:
                data_sources = data_source_storage.find_active_sources()
            else:
                data_sources = data_source_storage.find_many({})
        
        return [
            DataSourceListResponse(
                id=ds["id"],
                name=ds["name"],
                db_type=ds["db_type"],
                provider=ds["provider"],
                is_default=ds["is_default"],
                is_active=ds["is_active"]
            )
            for ds in data_sources
        ]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve data sources: {str(e)}"
        )


@router.get("/{data_source_id}", response_model=DataSourceResponse)
async def get_data_source(
    data_source_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Get a specific data source configuration"""
    try:
        data_source = data_source_storage.find_by_id(data_source_id)
        
        if not data_source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data source not found"
            )
        
        return DataSourceResponse(
            id=data_source["id"],
            name=data_source["name"],
            db_type=data_source["db_type"],
            provider=data_source["provider"],
            connection_params=data_source["connection_params"],
            is_default=data_source["is_default"],
            is_active=data_source["is_active"],
            date_created=data_source["date_created"],
            date_modified=data_source["date_modified"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve data source: {str(e)}"
        )


@router.put("/{data_source_id}", response_model=DataSourceResponse)
async def update_data_source(
    data_source_id: str,
    request: DataSourceUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    """Update a data source configuration"""
    try:
        # Check if data source exists
        existing_data_source = data_source_storage.find_by_id(data_source_id)
        if not existing_data_source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data source not found"
            )
        
        # Prepare update data
        update_data = {}
        
        if request.name is not None:
            update_data["name"] = request.name
        
        if request.credentials is not None:
            update_data["credentials"] = credential_encryption.encrypt_credentials(request.credentials)
        
        if request.connection_params is not None:
            update_data["connection_params"] = request.connection_params
        
        if request.is_active is not None:
            update_data["is_active"] = request.is_active
        
        if request.is_default is not None:
            update_data["is_default"] = request.is_default
            
            # If setting as default, unset existing defaults of the same type
            if request.is_default:
                db_type = existing_data_source["db_type"]
                existing_defaults = data_source_storage.find_by_type(db_type)
                for existing in existing_defaults:
                    if existing["id"] != data_source_id and existing.get("is_default", False):
                        data_source_storage.update_by_id(existing["id"], {"is_default": False})
        
        # Update the data source
        success = data_source_storage.update_by_id(data_source_id, update_data)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update data source"
            )
        
        # Remove cached connection if it exists
        connection_manager.remove_cached_connection(data_source_id)
        
        # Return updated data source
        updated_data_source = data_source_storage.find_by_id(data_source_id)
        
        return DataSourceResponse(
            id=updated_data_source["id"],
            name=updated_data_source["name"],
            db_type=updated_data_source["db_type"],
            provider=updated_data_source["provider"],
            connection_params=updated_data_source["connection_params"],
            is_default=updated_data_source["is_default"],
            is_active=updated_data_source["is_active"],
            date_created=updated_data_source["date_created"],
            date_modified=updated_data_source["date_modified"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update data source: {str(e)}"
        )


@router.delete("/{data_source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_data_source(
    data_source_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Delete a data source configuration"""
    try:
        # Check if data source exists
        existing_data_source = data_source_storage.find_by_id(data_source_id)
        if not existing_data_source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data source not found"
            )
        
        # Remove cached connection if it exists
        connection_manager.remove_cached_connection(data_source_id)
        
        # Delete the data source
        success = data_source_storage.delete_by_id(data_source_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete data source"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete data source: {str(e)}"
        )


@router.post("/{data_source_id}/test", response_model=DataSourceTestResponse)
async def test_data_source(
    data_source_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """Test connection to a data source"""
    try:
        # Check if data source exists
        existing_data_source = data_source_storage.find_by_id(data_source_id)
        if not existing_data_source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Data source not found"
            )
        
        # Test the connection using connection manager
        test_result = connection_manager.test_connection(data_source_id)
        
        return DataSourceTestResponse(
            success=test_result["success"],
            message=test_result["message"],
            details=test_result.get("details")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to test data source connection: {str(e)}"
        )