import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.storage import pattern_storage, user_storage
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


def test_create_pattern(auth_headers):
    test_pattern = {
        "name": "Test Pattern",
        "pattern_id": "TEST_001",
        "description": "This is a test pattern for validation",
        "full_description": "This is a comprehensive test pattern used for validation purposes in our testing framework"
    }
    
    response = client.post("/api/v1/patterns/", json=test_pattern, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_pattern["name"]
    assert data["pattern_id"] == test_pattern["pattern_id"]
    assert data["description"] == test_pattern["description"]
    assert data["full_description"] == test_pattern["full_description"]
    assert "id" in data
    assert "date_created" in data
    assert "date_modified" in data
    
    pattern_storage.delete_by_id(data["id"])


def test_create_pattern_without_full_description(auth_headers):
    test_pattern = {
        "name": "Simple Pattern",
        "pattern_id": "SIMPLE_001",
        "description": "This is a simple pattern without full description"
    }
    
    response = client.post("/api/v1/patterns/", json=test_pattern, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_pattern["name"]
    assert data["pattern_id"] == test_pattern["pattern_id"]
    assert data["description"] == test_pattern["description"]
    assert data["full_description"] is None
    assert "id" in data
    assert "date_created" in data
    assert "date_modified" in data
    
    pattern_storage.delete_by_id(data["id"])


def test_create_pattern_duplicate_pattern_id(auth_headers):
    test_pattern = {
        "name": "Duplicate Pattern",
        "pattern_id": "DUPLICATE_001",
        "description": "This pattern will be duplicated"
    }
    
    pattern_id = pattern_storage.create(test_pattern)
    
    response = client.post("/api/v1/patterns/", json=test_pattern, headers=auth_headers)
    assert response.status_code == 400
    assert "Pattern with this pattern_id already exists" in response.json()["detail"]
    
    pattern_storage.delete_by_id(pattern_id)


def test_list_patterns(auth_headers):
    test_pattern_1 = {
        "name": "Test Pattern 1",
        "pattern_id": "TEST_001",
        "description": "First test pattern"
    }
    test_pattern_2 = {
        "name": "Test Pattern 2",
        "pattern_id": "TEST_002",
        "description": "Second test pattern"
    }
    
    pattern_id_1 = pattern_storage.create(test_pattern_1)
    pattern_id_2 = pattern_storage.create(test_pattern_2)
    
    response = client.get("/api/v1/patterns/", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "patterns" in data
    assert "total" in data
    assert data["total"] >= 2
    
    pattern_names = [p["name"] for p in data["patterns"]]
    assert "Test Pattern 1" in pattern_names
    assert "Test Pattern 2" in pattern_names
    
    pattern_storage.delete_by_id(pattern_id_1)
    pattern_storage.delete_by_id(pattern_id_2)


def test_get_pattern_by_id(auth_headers):
    test_pattern = {
        "name": "Get Test Pattern",
        "pattern_id": "GET_TEST_001",
        "description": "This pattern is for get endpoint testing"
    }
    
    pattern_id = pattern_storage.create(test_pattern)
    
    response = client.get(f"/api/v1/patterns/{pattern_id}", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_pattern["name"]
    assert data["pattern_id"] == test_pattern["pattern_id"]
    assert data["description"] == test_pattern["description"]
    assert data["id"] == pattern_id
    
    pattern_storage.delete_by_id(pattern_id)


def test_get_pattern_not_found(auth_headers):
    response = client.get("/api/v1/patterns/nonexistent_id", headers=auth_headers)
    assert response.status_code == 404
    assert "Pattern not found" in response.json()["detail"]


def test_update_pattern(auth_headers):
    test_pattern = {
        "name": "Update Test Pattern",
        "pattern_id": "UPDATE_001",
        "description": "Original description"
    }
    
    pattern_id = pattern_storage.create(test_pattern)
    
    update_data = {
        "name": "Updated Pattern Name",
        "description": "Updated description",
        "full_description": "Updated comprehensive description"
    }
    
    response = client.put(f"/api/v1/patterns/{pattern_id}", json=update_data, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == update_data["name"]
    assert data["pattern_id"] == test_pattern["pattern_id"]  # Should remain unchanged
    assert data["description"] == update_data["description"]
    assert data["full_description"] == update_data["full_description"]
    
    pattern_storage.delete_by_id(pattern_id)


def test_update_pattern_with_duplicate_pattern_id(auth_headers):
    test_pattern_1 = {
        "name": "Pattern 1",
        "pattern_id": "UNIQUE_001",
        "description": "First pattern"
    }
    test_pattern_2 = {
        "name": "Pattern 2",
        "pattern_id": "UNIQUE_002",
        "description": "Second pattern"
    }
    
    pattern_id_1 = pattern_storage.create(test_pattern_1)
    pattern_id_2 = pattern_storage.create(test_pattern_2)
    
    update_data = {
        "pattern_id": "UNIQUE_001"  # Try to use existing pattern_id
    }
    
    response = client.put(f"/api/v1/patterns/{pattern_id_2}", json=update_data, headers=auth_headers)
    assert response.status_code == 400
    assert "Pattern with this pattern_id already exists" in response.json()["detail"]
    
    pattern_storage.delete_by_id(pattern_id_1)
    pattern_storage.delete_by_id(pattern_id_2)


def test_update_pattern_not_found(auth_headers):
    update_data = {
        "name": "Updated Name"
    }
    
    response = client.put("/api/v1/patterns/nonexistent_id", json=update_data, headers=auth_headers)
    assert response.status_code == 404
    assert "Pattern not found" in response.json()["detail"]


def test_update_pattern_no_fields(auth_headers):
    test_pattern = {
        "name": "No Update Pattern",
        "pattern_id": "NO_UPDATE_001",
        "description": "This pattern won't be updated"
    }
    
    pattern_id = pattern_storage.create(test_pattern)
    
    response = client.put(f"/api/v1/patterns/{pattern_id}", json={}, headers=auth_headers)
    assert response.status_code == 400
    assert "No fields to update" in response.json()["detail"]
    
    pattern_storage.delete_by_id(pattern_id)


def test_delete_pattern(auth_headers):
    test_pattern = {
        "name": "Delete Test Pattern",
        "pattern_id": "DELETE_001",
        "description": "This pattern will be deleted"
    }
    
    pattern_id = pattern_storage.create(test_pattern)
    
    response = client.delete(f"/api/v1/patterns/{pattern_id}", headers=auth_headers)
    assert response.status_code == 200
    assert "Pattern deleted successfully" in response.json()["message"]
    
    deleted_pattern = pattern_storage.find_by_id(pattern_id)
    assert deleted_pattern is None


def test_delete_pattern_not_found(auth_headers):
    response = client.delete("/api/v1/patterns/nonexistent_id", headers=auth_headers)
    assert response.status_code == 404
    assert "Pattern not found" in response.json()["detail"]


def test_unauthorized_access():
    response = client.get("/api/v1/patterns/")
    assert response.status_code == 401
    
    response = client.post("/api/v1/patterns/", json={})
    assert response.status_code == 401
    
    response = client.put("/api/v1/patterns/some_id", json={})
    assert response.status_code == 401
    
    response = client.delete("/api/v1/patterns/some_id")
    assert response.status_code == 401