# tests/e2e/test_full_journey.py
import requests
import pytest
from uuid import uuid4

def test_e2e_user_profile_flow(fastapi_server):
    """
    E2E TEST: Full User Journey
    Flow: Register -> Login -> View Profile -> Update Profile -> Change Password -> Re-Login
    """
    base_url = fastapi_server.rstrip("/")
    # Generate unique credentials to avoid collisions
    unique_id = str(uuid4())[:8]
    username = f"e2e_{unique_id}"
    email = f"e2e_{unique_id}@test.com"
    password = "StartPassword123!"
    
    # 1. Register
    reg_res = requests.post(f"{base_url}/auth/register", json={
        "email": email, "username": username,
        "password": password, "confirm_password": password,
        "first_name": "E2E", "last_name": "Start"
    })
    assert reg_res.status_code == 201

    # 2. Login (Get Token)
    login_res = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": password
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. View Profile (Verify "Unknown" bug is fixed)
    profile_res = requests.get(f"{base_url}/auth/me", headers=headers)
    assert profile_res.status_code == 200
    assert profile_res.json()["email"] == email  # Should be real email, not "unknown"

    # 4. Update Profile
    update_res = requests.put(f"{base_url}/auth/me", headers=headers, json={
        "first_name": "ChangedName",
        "last_name": "ChangedLast"
    })
    assert update_res.status_code == 200
    assert update_res.json()["first_name"] == "ChangedName"

    # 5. Change Password
    new_password = "EndPassword456!"
    pwd_res = requests.put(f"{base_url}/auth/password", headers=headers, json={
        "current_password": password,
        "new_password": new_password,
        "confirm_new_password": new_password
    })
    assert pwd_res.status_code == 200

    # 6. Verify Login: Old Password (Should Fail)
    fail_res = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": password
    })
    assert fail_res.status_code == 401

    # 7. Verify Login: New Password (Should Succeed)
    success_res = requests.post(f"{base_url}/auth/login", json={
        "username": username, "password": new_password
    })
    assert success_res.status_code == 200