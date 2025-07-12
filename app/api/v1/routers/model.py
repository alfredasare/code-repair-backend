from fastapi import APIRouter, HTTPException, status, Depends
from app.schemas.model import ModelCreate, ModelUpdate, ModelResponse, ModelListResponse
from app.schemas.user import UserResponse
from app.core.authentication.auth_middleware import get_current_user
from app.core.storage import model_storage

router = APIRouter()


@router.get("/", response_model=ModelListResponse)
async def list_models(current_user: UserResponse = Depends(get_current_user)):
    models_list = model_storage.find_many({})
    model_responses = [ModelResponse(**model) for model in models_list]
    return ModelListResponse(models=model_responses, total=len(model_responses))


@router.get("/{model_id}", response_model=ModelResponse)
async def get_model(model_id: str, current_user: UserResponse = Depends(get_current_user)):
    model = model_storage.find_by_id(model_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model not found"
        )
    return ModelResponse(**model)


@router.post("/", response_model=ModelResponse)
async def create_model(
    model_data: ModelCreate,
    current_user: UserResponse = Depends(get_current_user)
):
    existing_model = model_storage.find_by_model_id(model_data.model_id)
    if existing_model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Model with this model_id already exists"
        )
    
    model_dict = model_data.model_dump()
    created_model_id = model_storage.create(model_dict)
    
    created_model = model_storage.find_by_id(created_model_id)
    return ModelResponse(**created_model)


@router.put("/{model_id}", response_model=ModelResponse)
async def update_model(
    model_id: str,
    model_data: ModelUpdate,
    current_user: UserResponse = Depends(get_current_user)
):
    existing_model = model_storage.find_by_id(model_id)
    if not existing_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model not found"
        )
    
    update_dict = model_data.model_dump(exclude_unset=True)
    if not update_dict:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )
    
    if "model_id" in update_dict:
        existing_with_same_model_id = model_storage.find_by_model_id(update_dict["model_id"])
        if existing_with_same_model_id and existing_with_same_model_id["id"] != model_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Model with this model_id already exists"
            )
    
    success = model_storage.update_by_id(model_id, update_dict)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update model"
        )
    
    updated_model = model_storage.find_by_id(model_id)
    return ModelResponse(**updated_model)


@router.delete("/{model_id}")
async def delete_model(model_id: str, current_user: UserResponse = Depends(get_current_user)):
    model = model_storage.find_by_id(model_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model not found"
        )
    
    success = model_storage.delete_by_id(model_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete model"
        )
    
    return {"message": "Model deleted successfully"}