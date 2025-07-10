import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.storage import criteria_storage, user_storage
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


def test_create_criteria(auth_headers):
    test_criteria = {
        "name": "Test Criteria",
        "criteria": "This is a test criteria for evaluation",
        "evaluation_steps": [
            "Step 1: Review the input",
            "Step 2: Analyze the output",
            "Step 3: Compare with expected results"
        ]
    }
    
    response = client.post("/api/v1/settings/criteria/", json=test_criteria, headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_criteria["name"]
    assert data["criteria"] == test_criteria["criteria"]
    assert data["evaluation_steps"] == test_criteria["evaluation_steps"]
    assert "id" in data
    assert "date_created" in data
    assert "date_modified" in data
    
    criteria_storage.delete_by_id(data["id"])


def test_create_criteria_duplicate_name(auth_headers):
    test_criteria = {
        "name": "Duplicate Test",
        "criteria": "This is a test criteria",
        "evaluation_steps": ["Step 1"]
    }
    
    criteria_id = criteria_storage.create(test_criteria)
    
    response = client.post("/api/v1/settings/criteria/", json=test_criteria, headers=auth_headers)
    assert response.status_code == 400
    assert "Criteria with this name already exists" in response.json()["detail"]
    
    criteria_storage.delete_by_id(criteria_id)


def test_list_criteria(auth_headers):
    test_criteria_1 = {
        "name": "Test Criteria 1",
        "criteria": "First test criteria",
        "evaluation_steps": ["Step 1"]
    }
    test_criteria_2 = {
        "name": "Test Criteria 2",
        "criteria": "Second test criteria",
        "evaluation_steps": ["Step 1", "Step 2"]
    }
    
    criteria_id_1 = criteria_storage.create(test_criteria_1)
    criteria_id_2 = criteria_storage.create(test_criteria_2)
    
    response = client.get("/api/v1/settings/criteria/", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert "criteria" in data
    assert "total" in data
    assert data["total"] >= 2
    
    criteria_names = [c["name"] for c in data["criteria"]]
    assert "Test Criteria 1" in criteria_names
    assert "Test Criteria 2" in criteria_names
    
    criteria_storage.delete_by_id(criteria_id_1)
    criteria_storage.delete_by_id(criteria_id_2)


def test_get_criteria_by_id(auth_headers):
    test_criteria = {
        "name": "Get Test Criteria",
        "criteria": "This is a test criteria for get endpoint",
        "evaluation_steps": ["Step 1", "Step 2"]
    }
    
    criteria_id = criteria_storage.create(test_criteria)
    
    response = client.get(f"/api/v1/settings/criteria/{criteria_id}", headers=auth_headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["name"] == test_criteria["name"]
    assert data["criteria"] == test_criteria["criteria"]
    assert data["evaluation_steps"] == test_criteria["evaluation_steps"]
    assert data["id"] == criteria_id
    
    criteria_storage.delete_by_id(criteria_id)


def test_get_criteria_not_found(auth_headers):
    response = client.get("/api/v1/settings/criteria/nonexistent_id", headers=auth_headers)
    assert response.status_code == 404
    assert "Criteria not found" in response.json()["detail"]


def test_delete_criteria(auth_headers):
    test_criteria = {
        "name": "Delete Test Criteria",
        "criteria": "This criteria will be deleted",
        "evaluation_steps": ["Step 1"]
    }
    
    criteria_id = criteria_storage.create(test_criteria)
    
    response = client.delete(f"/api/v1/settings/criteria/{criteria_id}", headers=auth_headers)
    assert response.status_code == 200
    assert "Criteria deleted successfully" in response.json()["message"]
    
    deleted_criteria = criteria_storage.find_by_id(criteria_id)
    assert deleted_criteria is None


def test_delete_criteria_not_found(auth_headers):
    response = client.delete("/api/v1/settings/criteria/nonexistent_id", headers=auth_headers)
    assert response.status_code == 404
    assert "Criteria not found" in response.json()["detail"]


def test_unauthorized_access():
    response = client.get("/api/v1/settings/criteria/")
    assert response.status_code == 401
    
    response = client.post("/api/v1/settings/criteria/", json={})
    assert response.status_code == 401
    
    response = client.delete("/api/v1/settings/criteria/some_id")
    assert response.status_code == 401