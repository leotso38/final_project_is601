# tests/integration/test_profile_api.py
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User
from app.core.security import verify_password

# Initialize client locally for this module
client = TestClient(app)

@pytest.fixture
def auth_headers(db_session):
    """
    Helper fixture to create a user with a KNOWN password 
    and return their auth headers.
    """
    password = "KnownPassword123!"
    user_data = {
        "first_name": "Integ",
        "last_name": "User",
        "email": "integ@test.com",
        "username": "integuser",
        "password": User.hash_password(password)
    }
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    
    # Login to get token
    response = client.post("/auth/login", json={
        "username": "integuser", 
        "password": password
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_update_profile_integration(auth_headers, db_session):
    """
    INTEGRATION TEST: Verifies PUT /auth/me updates the DB.
    """
    # 1. Act: Update profile via API
    payload = {
        "first_name": "UpdatedName",
        "last_name": "UpdatedLast",
        "email": "new.email@test.com"
    }
    response = client.put("/auth/me", json=payload, headers=auth_headers)
    
    # 2. Assert API Response
    assert response.status_code == 200
    data = response.json()
    assert data["first_name"] == "UpdatedName"
    
    # 3. Assert Database State (Direct DB check)
    # We query the DB to ensure the API actually saved the data
    user_in_db = db_session.query(User).filter(User.username == "integuser").first()
    assert user_in_db.email == "new.email@test.com"
    assert user_in_db.last_name == "UpdatedLast"

def test_change_password_integration(auth_headers, db_session):
    """
    INTEGRATION TEST: Verifies PUT /auth/password updates the hash.
    """
    # 1. Act: Change Password
    payload = {
        "current_password": "KnownPassword123!",
        "new_password": "NewSecurePass999!",
        "confirm_new_password": "NewSecurePass999!"
    }
    response = client.put("/auth/password", json=payload, headers=auth_headers)
    assert response.status_code == 200

    # 2. Assert Database State
    user_in_db = db_session.query(User).filter(User.username == "integuser").first()
    # Verify the hash in the DB matches the new password
    assert verify_password("NewSecurePass999!", user_in_db.password)
    # Verify the old password no longer works
    assert not verify_password("KnownPassword123!", user_in_db.password)