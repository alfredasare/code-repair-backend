from typing import List
from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.criteria import CriteriaCreate, CriteriaResponse, CriteriaListResponse
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.storage import criteria_storage

router = APIRouter()


@router.get("/", response_model=CriteriaListResponse)
async def list_criteria(current_user: UserResponse = Depends(get_current_user)):
    criteria_list = criteria_storage.find_many({})
    criteria_responses = [CriteriaResponse(**criteria) for criteria in criteria_list]
    return CriteriaListResponse(criteria=criteria_responses, total=len(criteria_responses))


@router.get("/{criteria_id}", response_model=CriteriaResponse)
async def get_criteria(criteria_id: str, current_user: UserResponse = Depends(get_current_user)):
    criteria = criteria_storage.find_by_id(criteria_id)
    if not criteria:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Criteria not found"
        )
    return CriteriaResponse(**criteria)


@router.post("/", response_model=CriteriaResponse)
async def create_criteria(
    criteria_data: CriteriaCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    existing_criteria = criteria_storage.find_by_name(criteria_data.name)
    if existing_criteria:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Criteria with this name already exists"
        )
    
    criteria_dict = criteria_data.model_dump()
    criteria_id = criteria_storage.create(criteria_dict)
    
    created_criteria = criteria_storage.find_by_id(criteria_id)
    return CriteriaResponse(**created_criteria)


@router.delete("/{criteria_id}")
async def delete_criteria(criteria_id: str, current_user: UserResponse = Depends(get_current_user)):
    criteria = criteria_storage.find_by_id(criteria_id)
    if not criteria:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Criteria not found"
        )
    
    success = criteria_storage.delete_by_id(criteria_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete criteria"
        )
    
    return {"message": "Criteria deleted successfully"}