import json
import pytest
from app.utils.Constants import Messages
from app.repositories.user_repository import UserRepository

def test_login_success(client, init_database):
    payload = {"username": "testuser", "password": "testpass"}
    response = client.post("/api/v1/login/", json=payload)
    data = response.get_json()
    
    assert response.status_code == 200
    assert data["success"] is True
    assert "token" in data["data"]


def test_login_wrong_password(client, init_database):
    payload = {"username": "testuser", "password": "wrongpass"}
    response = client.post("/api/v1/login/", json=payload)
    data = response.get_json()
    
    assert response.status_code == 404
    assert data["success"] is False
    assert data["message"] == "User not found" or data["message"] == Messages.USER_NOT_FOUND


def test_login_invalid_user(client, init_database):
    payload = {"username": "unknown", "password": "testpass"}
    response = client.post("/api/v1/login/", json=payload)
    data = response.get_json()
    
    assert response.status_code == 200
    assert data["success"] is False
    assert data["message"] == Messages.INVALID_REQUEST
