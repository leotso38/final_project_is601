import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException, status
from app.auth.dependencies import get_current_user, get_current_active_user
from app.schemas.user import UserResponse
from app.models.user import User
from uuid import uuid4
from datetime import datetime, timezone

# 1. FIX DATA: Add "sub" key to mimic a decoded JWT payload
user_id = uuid4()
sample_user_data = {
    "sub": str(user_id),  # Required by get_current_user
    "id": user_id,
    "username": "testuser",
    "email": "test@example.com",
    "first_name": "Test",
    "last_name": "User",
    "is_active": True,
    "is_verified": True,
    "created_at": datetime.now(timezone.utc),
    "updated_at": datetime.now(timezone.utc)
}

inactive_user_data = {
    "sub": str(uuid4()),
    "id": uuid4(),
    "username": "inactiveuser",
    "email": "inactive@example.com",
    "first_name": "Inactive",
    "last_name": "User",
    "is_active": False,
    "is_verified": False,
    "created_at": datetime.now(timezone.utc),
    "updated_at": datetime.now(timezone.utc)
}

# Fixture for mocking token verification
@pytest.fixture
def mock_verify_token():
    with patch.object(User, 'verify_token') as mock:
        yield mock

# 2. FIX DB: Fixture to mock the database session
@pytest.fixture
def mock_db():
    session = MagicMock()
    return session

def test_get_current_user_valid_token_existing_user(mock_verify_token, mock_db):
    """
    Test that get_current_user queries the DB and returns the user object.
    """
    # Arrange
    mock_verify_token.return_value = sample_user_data
    
    # Mock the DB query chain: db.query(User).filter(...).first()
    # We create a mock User object to return
    mock_user_obj = MagicMock()
    mock_user_obj.id = sample_user_data["id"]
    mock_user_obj.username = sample_user_data["username"]
    mock_user_obj.is_active = True
    
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user_obj

    # Act: Pass the mock_db explicitly
    user = get_current_user(token="validtoken", db=mock_db)

    # Assert
    assert user.id == sample_user_data["id"]
    assert user.username == sample_user_data["username"]
    mock_verify_token.assert_called_once_with("validtoken")
    # Verify DB was queried
    mock_db.query.assert_called_once()

def test_get_current_user_invalid_token(mock_verify_token, mock_db):
    mock_verify_token.return_value = None

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token="invalidtoken", db=mock_db)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"

def test_get_current_user_valid_token_user_not_found(mock_verify_token, mock_db):
    """Test when token is valid but user is not in DB (e.g. deleted)."""
    mock_verify_token.return_value = sample_user_data
    
    # Mock DB returning None
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token="validtoken", db=mock_db)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_active_user_active():
    """Test get_current_active_user with an active user object."""
    # We just pass a user object directly, no need to mock get_current_user dependencies here
    mock_user = MagicMock()
    mock_user.is_active = True
    
    result = get_current_active_user(current_user=mock_user)
    assert result == mock_user

def test_get_current_active_user_inactive():
    """Test get_current_active_user with an inactive user object."""
    mock_user = MagicMock()
    mock_user.is_active = False

    with pytest.raises(HTTPException) as exc_info:
        get_current_active_user(current_user=mock_user)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "Inactive user"

def test_get_current_user_token_missing_sub(mock_verify_token, mock_db):
    """
    Test a valid token payload that is missing the 'sub' field.
    This hits the 'if user_id is None:' check.
    """
    # Return a dict that has no 'sub' key
    mock_verify_token.return_value = {"username": "nosub"} 

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token="valid_token_no_sub", db=mock_db)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"    
# Add this to tests/integration/test_dependencies.py

def test_get_current_user_token_missing_sub(mock_verify_token, mock_db):
    """
    Test a valid token payload that is missing the 'sub' field.
    This hits the 'if user_id is None:' check in dependencies.py.
    """
    # Return a dict that has no 'sub' key
    mock_verify_token.return_value = {"username": "nosub"} 

    with pytest.raises(HTTPException) as exc_info:
        get_current_user(token="valid_token_no_sub", db=mock_db)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc_info.value.detail == "Could not validate credentials"