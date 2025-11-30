import pytest
from pydantic import ValidationError
from app.schemas.user import UserCreate, PasswordUpdate

def test_user_create_password_too_short():
    with pytest.raises(ValidationError) as exc:
        UserCreate(
            first_name="Test", last_name="User", email="test@example.com",
            username="testuser", password="Ab1!", confirm_password="Ab1!"
        )
    assert "at least 8 characters" in str(exc.value)

def test_user_create_password_no_upper():
    with pytest.raises(ValidationError) as exc:
        UserCreate(
            first_name="Test", last_name="User", email="test@example.com",
            username="testuser", password="password123!", confirm_password="password123!"
        )
    assert "at least one uppercase" in str(exc.value)

def test_user_create_password_no_lower():
    with pytest.raises(ValidationError) as exc:
        UserCreate(
            first_name="Test", last_name="User", email="test@example.com",
            username="testuser", password="PASSWORD123!", confirm_password="PASSWORD123!"
        )
    assert "at least one lowercase" in str(exc.value)

def test_user_create_password_no_digit():
    with pytest.raises(ValidationError) as exc:
        UserCreate(
            first_name="Test", last_name="User", email="test@example.com",
            username="testuser", password="Password!", confirm_password="Password!"
        )
    assert "at least one digit" in str(exc.value)

def test_user_create_password_no_special():
    with pytest.raises(ValidationError) as exc:
        UserCreate(
            first_name="Test", last_name="User", email="test@example.com",
            username="testuser", password="Password123", confirm_password="Password123"
        )
    assert "at least one special" in str(exc.value)

def test_user_create_password_mismatch():
    with pytest.raises(ValidationError) as exc:
        UserCreate(
            first_name="Test", last_name="User", email="test@example.com",
            username="testuser", password="SecurePass123!", confirm_password="DifferentPass123!"
        )
    assert "match" in str(exc.value)

def test_password_update_mismatch():
    with pytest.raises(ValidationError) as exc:
        PasswordUpdate(
            current_password="OldPass123!",
            new_password="NewPass123!",
            confirm_new_password="DifferentPass123!"
        )
    assert "do not match" in str(exc.value)

def test_password_update_same_as_current():
    with pytest.raises(ValidationError) as exc:
        PasswordUpdate(
            current_password="SamePass123!",
            new_password="SamePass123!",
            confirm_new_password="SamePass123!"
        )
    assert "must be different" in str(exc.value)