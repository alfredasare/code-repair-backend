import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.storage import user_storage
from app.core.authentication.hashing import hash_password
from app.core.authentication.auth_token import create_access_token, decode_token

client = TestClient(app)


def test_register_user():
    test_user = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123"
    }
    
    response = client.post("/api/v1/auth/register", json=test_user)
    assert response.status_code == 200
    assert "message" in response.json()
    assert "user_id" in response.json()
    
    user_storage.delete_one({"email": test_user["email"]})


def test_register_duplicate_email():
    test_user = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123"
    }
    
    client.post("/api/v1/auth/register", json=test_user)
    
    response = client.post("/api/v1/auth/register", json=test_user)
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]
    
    user_storage.delete_one({"email": test_user["email"]})


def test_login_success():
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
    user_storage.create(user_data)
    
    login_data = {
        "username": test_user["email"],
        "password": test_user["password"]
    }
    
    response = client.post("/api/v1/auth/login", data=login_data)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    
    user_storage.delete_one({"email": test_user["email"]})


def test_login_invalid_credentials():
    login_data = {
        "username": "nonexistent@example.com",
        "password": "wrongpassword"
    }
    
    response = client.post("/api/v1/auth/login", data=login_data)
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]


def test_token_creation_and_validation():
    user_id = "test_user_id"
    
    token = create_access_token(user_id)
    assert isinstance(token, str)
    
    decoded_user_id = decode_token(token)
    assert decoded_user_id == user_id


def test_invalid_token():
    invalid_token = "invalid.token.here"
    decoded_user_id = decode_token(invalid_token)
    assert decoded_user_id is None