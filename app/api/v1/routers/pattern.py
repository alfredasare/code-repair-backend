from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.pattern import PatternCreate, PatternUpdate, PatternResponse, PatternListResponse
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.storage import pattern_storage

router = APIRouter()


@router.get("/", response_model=PatternListResponse)
async def list_patterns(current_user: UserResponse = Depends(get_current_user)):
    patterns_list = pattern_storage.find_many({})
    pattern_responses = [PatternResponse(**pattern) for pattern in patterns_list]
    return PatternListResponse(patterns=pattern_responses, total=len(pattern_responses))


@router.get("/{pattern_id}", response_model=PatternResponse)
async def get_pattern(pattern_id: str, current_user: UserResponse = Depends(get_current_user)):
    pattern = pattern_storage.find_by_id(pattern_id)
    if not pattern:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pattern not found"
        )
    return PatternResponse(**pattern)


@router.post("/", response_model=PatternResponse)
async def create_pattern(
    pattern_data: PatternCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    existing_pattern = pattern_storage.find_by_pattern_id(pattern_data.pattern_id)
    if existing_pattern:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pattern with this pattern_id already exists"
        )
    
    pattern_dict = pattern_data.model_dump()
    created_pattern_id = pattern_storage.create(pattern_dict)
    
    created_pattern = pattern_storage.find_by_id(created_pattern_id)
    return PatternResponse(**created_pattern)


@router.put("/{pattern_id}", response_model=PatternResponse)
async def update_pattern(
    pattern_id: str,
    pattern_data: PatternUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    existing_pattern = pattern_storage.find_by_id(pattern_id)
    if not existing_pattern:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pattern not found"
        )
    
    update_dict = pattern_data.model_dump(exclude_unset=True)
    if not update_dict:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )
    
    if "pattern_id" in update_dict:
        existing_with_same_pattern_id = pattern_storage.find_by_pattern_id(update_dict["pattern_id"])
        if existing_with_same_pattern_id and existing_with_same_pattern_id["id"] != pattern_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Pattern with this pattern_id already exists"
            )
    
    success = pattern_storage.update_by_id(pattern_id, update_dict)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update pattern"
        )
    
    updated_pattern = pattern_storage.find_by_id(pattern_id)
    return PatternResponse(**updated_pattern)


@router.delete("/{pattern_id}")
async def delete_pattern(pattern_id: str, current_user: UserResponse = Depends(get_current_user)):
    pattern = pattern_storage.find_by_id(pattern_id)
    if not pattern:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pattern not found"
        )
    
    success = pattern_storage.delete_by_id(pattern_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete pattern"
        )
    
    return {"message": "Pattern deleted successfully"}