# tests/integration/test_profile_api.py
import pytest
from uuid import uuid4
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
    
    Generates UNIQUE credentials for every test to avoid DB collisions.
    """
    password = "KnownPassword123!"
    unique_id = str(uuid4())
    username = f"integuser_{unique_id}"
    email = f"integ_{unique_id}@test.com"
    
    user_data = {
        "first_name": "Integ",
        "last_name": "User",
        "email": email,
        "username": username,
        "password": User.hash_password(password)
    }
    user = User(**user_data)
    db_session.add(user)
    db_session.commit()
    
    # Login to get token
    response = client.post("/auth/login", json={
        "username": username, 
        "password": password
    })
    token = response.json()["access_token"]
    
    # Return the headers AND the username so the test knows who to look for
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "username": username
    }

def test_update_profile_integration(auth_headers, db_session):
    """
    INTEGRATION TEST: Verifies PUT /auth/me updates the DB.
    """
    headers = auth_headers["headers"]
    username = auth_headers["username"]
    
    # 1. Act: Update profile via API
    payload = {
        "first_name": "UpdatedName",
        "last_name": "UpdatedLast",
        "email": f"new_{uuid4()}@test.com" # Ensure new email is also unique
    }
    response = client.put("/auth/me", json=payload, headers=headers)
    
    # 2. Assert API Response
    assert response.status_code == 200, f"Update failed: {response.text}"
    data = response.json()
    assert data["first_name"] == "UpdatedName"
    
    # 3. Assert Database State (Direct DB check)
    user_in_db = db_session.query(User).filter(User.username == username).first()
    assert user_in_db.email == payload["email"]
    assert user_in_db.last_name == "UpdatedLast"

def test_change_password_integration(auth_headers, db_session):
    """
    INTEGRATION TEST: Verifies PUT /auth/password updates the hash.
    """
    headers = auth_headers["headers"]
    username = auth_headers["username"]
    
    # 1. Act: Change Password
    payload = {
        "current_password": "KnownPassword123!",
        "new_password": "NewSecurePass999!",
        "confirm_new_password": "NewSecurePass999!"
    }
    response = client.put("/auth/password", json=payload, headers=headers)
    assert response.status_code == 200, f"Password change failed: {response.text}"

    # 2. Assert Database State
    user_in_db = db_session.query(User).filter(User.username == username).first()
    
    # Verify the hash in the DB matches the new password
    # Note: verify_password takes (plain, hashed)
    assert verify_password("NewSecurePass999!", user_in_db.password)
    # Verify the old password no longer works
    assert not verify_password("KnownPassword123!", user_in_db.password)