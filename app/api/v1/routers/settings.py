from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.settings import SettingsCreate, SettingsUpdate, SettingsResponse
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.storage import settings_storage

router = APIRouter()


@router.get("/", response_model=SettingsResponse)
async def get_user_settings(current_user: UserResponse = Depends(get_current_user)):
    """Get the current user's settings"""
    try:
        settings = settings_storage.find_by_user_id(current_user.id)
        if not settings:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Settings not found"
            )
        return settings
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get settings: {str(e)}"
        )


@router.post("/", response_model=SettingsResponse)
async def create_user_settings(
    settings_data: SettingsCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    """Create settings for the current user"""
    try:
        existing_settings = settings_storage.find_by_user_id(current_user.id)
        if existing_settings:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Settings already exist for this user"
            )
        
        data = settings_data.model_dump()
        data["user_id"] = current_user.id
        
        settings_id = settings_storage.create(data)
        created_settings = settings_storage.find_by_id(settings_id)
        
        return created_settings
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create settings: {str(e)}"
        )


@router.put("/", response_model=SettingsResponse)
async def update_user_settings(
    settings_data: SettingsUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    """Update the current user's settings"""
    try:
        settings = settings_storage.find_by_user_id(current_user.id)
        if not settings:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Settings not found"
            )
        
        update_data = settings_data.model_dump(exclude_unset=True)
        success = settings_storage.update_by_id(settings["id"], update_data)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update settings"
            )
        
        updated_settings = settings_storage.find_by_id(settings["id"])
        return updated_settings
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update settings: {str(e)}"
        )


@router.delete("/")
async def delete_user_settings(current_user: UserResponse = Depends(get_current_user)):
    """Delete the current user's settings"""
    try:
        settings = settings_storage.find_by_user_id(current_user.id)
        if not settings:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Settings not found"
            )
        
        success = settings_storage.delete_by_id(settings["id"])
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete settings"
            )
        
        return {"message": "Settings deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete settings: {str(e)}"
        )