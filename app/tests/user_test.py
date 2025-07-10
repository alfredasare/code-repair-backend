import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.storage import user_storage
from app.core.authentication.hashing import hash_password
from app.core.authentication.auth_token import create_access_token

client = TestClient(app)


def test_get_current_user_success():
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
    response = client.get("/api/v1/users/me", headers=headers)
    
    assert response.status_code == 200
    user_response = response.json()
    assert user_response["username"] == test_user["username"]
    assert user_response["email"] == test_user["email"]
    assert user_response["is_active"] is True
    assert "id" in user_response
    assert "date_created" in user_response
    assert "date_modified" in user_response
    
    user_storage.delete_by_id(user_id)


def test_get_current_user_unauthorized():
    response = client.get("/api/v1/users/me")
    assert response.status_code == 401


def test_get_current_user_invalid_token():
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401


def test_get_current_user_inactive():
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
        "is_active": False
    }
    user_id = user_storage.create(user_data)
    
    token = create_access_token(user_id)
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/v1/users/me", headers=headers)
    
    assert response.status_code == 401
    assert "Inactive user" in response.json()["detail"]
    
    user_storage.delete_by_id(user_id)