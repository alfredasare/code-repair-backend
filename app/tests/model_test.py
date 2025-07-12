import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.storage import model_storage, user_storage
from app.core.authentication.hashing import hash_password
from app.core.authentication.auth_token import create_access_token

client = TestClient(app)


@pytest.fixture
def auth_headers():
    test_user = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123"
    }
    
    hashed_password = hash_password(test_user["password"])
    user_data = {
        "username": test_user["username"],
        "email": test_user["email"],
        "password_hash": hashed_password,
        "is_active": True
    }
    user_id = user_storage.create(user_data)
    
    token = create_access_token(user_id)
    headers = {"Authorization": f"Bearer {token}"}
    
    yield headers
    
    user_storage.delete_by_id(user_id)


def test_create_model_openai(auth_headers):
    test_model = {
        "name": "GPT-4",
        "model_id": "gpt-4-turbo",
        "type": "openai"
    }
    
    response = client.post("/api/v1/models/", json=test_model, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_model["name"]
    assert data["model_id"] == test_model["model_id"]
    assert data["type"] == test_model["type"]
    assert "id" in data
    assert "date_created" in data
    assert "date_modified" in data
    
    model_storage.delete_by_id(data["id"])


def test_create_model_groq(auth_headers):
    test_model = {
        "name": "Llama 3.1",
        "model_id": "llama-3.1-70b-versatile",
        "type": "groq"
    }
    
    response = client.post("/api/v1/models/", json=test_model, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_model["name"]
    assert data["model_id"] == test_model["model_id"]
    assert data["type"] == test_model["type"]
    
    model_storage.delete_by_id(data["id"])


def test_create_model_invalid_type(auth_headers):
    test_model = {
        "name": "Invalid Model",
        "model_id": "invalid-model",
        "type": "invalid_type"
    }
    
    response = client.post("/api/v1/models/", json=test_model, headers=auth_headers)
    assert response.status_code == 422  # Validation error


def test_create_model_duplicate_model_id(auth_headers):
    test_model = {
        "name": "Duplicate Model",
        "model_id": "duplicate-model-id",
        "type": "openai"
    }
    
    model_id = model_storage.create(test_model)
    
    response = client.post("/api/v1/models/", json=test_model, headers=auth_headers)
    assert response.status_code == 400
    assert "Model with this model_id already exists" in response.json()["detail"]
    
    model_storage.delete_by_id(model_id)


def test_list_models(auth_headers):
    test_model_1 = {
        "name": "GPT-3.5",
        "model_id": "gpt-3.5-turbo",
        "type": "openai"
    }
    test_model_2 = {
        "name": "Mixtral",
        "model_id": "mixtral-8x7b-32768",
        "type": "groq"
    }
    
    model_id_1 = model_storage.create(test_model_1)
    model_id_2 = model_storage.create(test_model_2)
    
    response = client.get("/api/v1/models/", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "models" in data
    assert "total" in data
    assert data["total"] >= 2
    
    model_names = [m["name"] for m in data["models"]]
    assert "GPT-3.5" in model_names
    assert "Mixtral" in model_names
    
    model_storage.delete_by_id(model_id_1)
    model_storage.delete_by_id(model_id_2)


def test_get_model_by_id(auth_headers):
    test_model = {
        "name": "Test Model",
        "model_id": "test-model-get",
        "type": "openai"
    }
    
    model_id = model_storage.create(test_model)
    
    response = client.get(f"/api/v1/models/{model_id}", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_model["name"]
    assert data["model_id"] == test_model["model_id"]
    assert data["type"] == test_model["type"]
    assert data["id"] == model_id
    
    model_storage.delete_by_id(model_id)


def test_get_model_not_found(auth_headers):
    response = client.get("/api/v1/models/nonexistent_id", headers=auth_headers)
    assert response.status_code == 404
    assert "Model not found" in response.json()["detail"]


def test_update_model(auth_headers):
    test_model = {
        "name": "Original Model",
        "model_id": "original-model",
        "type": "openai"
    }
    
    model_id = model_storage.create(test_model)
    
    update_data = {
        "name": "Updated Model Name",
        "type": "groq"
    }
    
    response = client.put(f"/api/v1/models/{model_id}", json=update_data, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == update_data["name"]
    assert data["model_id"] == test_model["model_id"]  # Should remain unchanged
    assert data["type"] == update_data["type"]
    
    model_storage.delete_by_id(model_id)


def test_update_model_with_duplicate_model_id(auth_headers):
    test_model_1 = {
        "name": "Model 1",
        "model_id": "unique-model-1",
        "type": "openai"
    }
    test_model_2 = {
        "name": "Model 2",
        "model_id": "unique-model-2",
        "type": "groq"
    }
    
    model_id_1 = model_storage.create(test_model_1)
    model_id_2 = model_storage.create(test_model_2)
    
    update_data = {
        "model_id": "unique-model-1"  # Try to use existing model_id
    }
    
    response = client.put(f"/api/v1/models/{model_id_2}", json=update_data, headers=auth_headers)
    assert response.status_code == 400
    assert "Model with this model_id already exists" in response.json()["detail"]
    
    model_storage.delete_by_id(model_id_1)
    model_storage.delete_by_id(model_id_2)


def test_update_model_invalid_type(auth_headers):
    test_model = {
        "name": "Test Model",
        "model_id": "test-model-update",
        "type": "openai"
    }
    
    model_id = model_storage.create(test_model)
    
    update_data = {
        "type": "invalid_type"
    }
    
    response = client.put(f"/api/v1/models/{model_id}", json=update_data, headers=auth_headers)
    assert response.status_code == 422  # Validation error
    
    model_storage.delete_by_id(model_id)


def test_update_model_not_found(auth_headers):
    update_data = {
        "name": "Updated Name"
    }
    
    response = client.put("/api/v1/models/nonexistent_id", json=update_data, headers=auth_headers)
    assert response.status_code == 404
    assert "Model not found" in response.json()["detail"]


def test_update_model_no_fields(auth_headers):
    test_model = {
        "name": "No Update Model",
        "model_id": "no-update-model",
        "type": "openai"
    }
    
    model_id = model_storage.create(test_model)
    
    response = client.put(f"/api/v1/models/{model_id}", json={}, headers=auth_headers)
    assert response.status_code == 400
    assert "No fields to update" in response.json()["detail"]
    
    model_storage.delete_by_id(model_id)


def test_delete_model(auth_headers):
    test_model = {
        "name": "Delete Test Model",
        "model_id": "delete-test-model",
        "type": "groq"
    }
    
    model_id = model_storage.create(test_model)
    
    response = client.delete(f"/api/v1/models/{model_id}", headers=auth_headers)
    assert response.status_code == 200
    assert "Model deleted successfully" in response.json()["message"]
    
    deleted_model = model_storage.find_by_id(model_id)
    assert deleted_model is None


def test_delete_model_not_found(auth_headers):
    response = client.delete("/api/v1/models/nonexistent_id", headers=auth_headers)
    assert response.status_code == 404
    assert "Model not found" in response.json()["detail"]


def test_unauthorized_access():
    response = client.get("/api/v1/models/")
    assert response.status_code == 401
    
    response = client.post("/api/v1/models/", json={})
    assert response.status_code == 401
    
    response = client.put("/api/v1/models/some_id", json={})
    assert response.status_code == 401
    
    response = client.delete("/api/v1/models/some_id")
    assert response.status_code == 401