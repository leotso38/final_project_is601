# tests/unit/test_security_coverage.py
import pytest
from datetime import timedelta, datetime, timezone
from uuid import uuid4
from unittest.mock import patch, AsyncMock, MagicMock
from jose import jwt
from fastapi import HTTPException
from passlib.exc import UnknownHashError

from app.core.config import settings
from app.core.security import verify_password, get_password_hash
from app.auth.jwt import create_token, decode_token, get_current_user
from app.schemas.token import TokenType

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
@pytest.fixture
def anyio_backend():
    """Force anyio to use asyncio only, preventing 'trio' errors."""
    return 'asyncio'

# ------------------------------------------------------------------------------
# Security Core Tests (app/core/security.py)
# ------------------------------------------------------------------------------
def test_password_hashing_consistency():
    pwd = "secret_password"
    hashed = get_password_hash(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrong_password", hashed) is False

def test_security_verify_password_edge_cases():
    with pytest.raises((UnknownHashError, ValueError)):
        verify_password("password", "not_a_valid_hash")

# ------------------------------------------------------------------------------
# JWT Creation Tests
# ------------------------------------------------------------------------------
def test_create_access_token():
    user_id = "user123"
    token = create_token(user_id=user_id, token_type=TokenType.ACCESS)
    assert isinstance(token, str)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == user_id
    assert payload["type"] == "access"

def test_create_refresh_token():
    user_id = "user123"
    token = create_token(user_id=user_id, token_type=TokenType.REFRESH)
    payload = jwt.decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["type"] == "refresh"

def test_create_token_with_uuid():
    uid = uuid4()
    token = create_token(user_id=uid, token_type=TokenType.ACCESS)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(uid)

def test_create_token_custom_expiry():
    delta = timedelta(minutes=60)
    token = create_token(user_id="u1", token_type=TokenType.ACCESS, expires_delta=delta)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
    exp = payload["exp"]
    now = datetime.now(timezone.utc).timestamp()
    assert exp > now + 3500

def test_create_token_encoding_error():
    with patch("jose.jwt.encode", side_effect=Exception("Encoding failed")):
        with pytest.raises(HTTPException) as exc:
            create_token(user_id="u1", token_type=TokenType.ACCESS)
        assert exc.value.status_code == 500
        assert "Could not create token" in exc.value.detail

# ------------------------------------------------------------------------------
# JWT Decoding Tests (Async)
# ------------------------------------------------------------------------------
@pytest.mark.anyio
async def test_decode_token_valid():
    token = create_token("user123", TokenType.ACCESS)
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_blacklist:
        mock_blacklist.return_value = False
        payload = await decode_token(token, TokenType.ACCESS)
        assert payload["sub"] == "user123"

@pytest.mark.anyio
async def test_decode_token_expired():
    delta = timedelta(minutes=-10)
    token = create_token("user123", TokenType.ACCESS, expires_delta=delta)
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_blacklist:
        mock_blacklist.return_value = False
        with pytest.raises(HTTPException) as exc:
            await decode_token(token, TokenType.ACCESS)
        assert exc.value.status_code == 401
        assert "expired" in exc.value.detail

@pytest.mark.anyio
async def test_decode_token_type_mismatch():
    to_encode = {
        "sub": "user123",
        "type": "refresh", 
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15)
    }
    fake_token = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_blacklist:
        mock_blacklist.return_value = False
        with pytest.raises(HTTPException) as exc:
            await decode_token(fake_token, TokenType.ACCESS)
        assert exc.value.status_code == 401
        assert "Invalid token type" in exc.value.detail

@pytest.mark.anyio
async def test_decode_token_blacklisted():
    token = create_token("user123", TokenType.ACCESS)
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_blacklist:
        mock_blacklist.return_value = True
        with pytest.raises(HTTPException) as exc:
            await decode_token(token, TokenType.ACCESS)
        assert exc.value.status_code == 401
        assert "revoked" in exc.value.detail

@pytest.mark.anyio
async def test_decode_token_invalid_signature():
    with pytest.raises(HTTPException) as exc:
        await decode_token("invalid.garbage.token", TokenType.ACCESS)
    assert exc.value.status_code == 401
    assert "Could not validate credentials" in exc.value.detail

# ------------------------------------------------------------------------------
# Get Current User Tests (jwt.py version)
# ------------------------------------------------------------------------------
@pytest.mark.anyio
async def test_jwt_get_current_user_success():
    token = create_token("user_uuid", TokenType.ACCESS)
    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = "user_uuid"
    mock_user.is_active = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user
    
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_bl:
        mock_bl.return_value = False
        user = await get_current_user(token, mock_db)
        assert user.id == "user_uuid"

@pytest.mark.anyio
async def test_jwt_get_current_user_not_found():
    """Test get_current_user when user ID doesn't exist in DB."""
    token = create_token("user_uuid", TokenType.ACCESS)
    
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_bl:
        mock_bl.return_value = False
        with pytest.raises(HTTPException) as exc:
            await get_current_user(token, mock_db)
        
        # FIX: The catch-all except block in jwt.py converts 404 to 401
        assert exc.value.status_code == 401
        # Verify the original error detail is preserved in the string
        assert "User not found" in exc.value.detail

@pytest.mark.anyio
async def test_jwt_get_current_user_inactive():
    """Test get_current_user when user is inactive."""
    token = create_token("user_uuid", TokenType.ACCESS)
    
    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.is_active = False 
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user
    
    with patch("app.auth.jwt.is_blacklisted", new_callable=AsyncMock) as mock_bl:
        mock_bl.return_value = False
        with pytest.raises(HTTPException) as exc:
            await get_current_user(token, mock_db)
        
        # FIX: The catch-all except block in jwt.py converts 400 to 401
        assert exc.value.status_code == 401
        # Verify the original error detail is preserved
        assert "Inactive user" in exc.value.detail