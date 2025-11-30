import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.database import Base, get_db

# Explicitly import models to ensure they are registered with Base.metadata
from app.models.user import User
from app.models.calculation import Calculation

# ------------------------------------------------------------------------------
# Isolated Test Setup
# ------------------------------------------------------------------------------
# Use a fresh in-memory database for this module
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    """Dependency override to use the test database session."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture(autouse=True)
def setup_dependency_overrides():
    """
    Force clean dependency overrides for each test.
    This prevents conflicts with other test files (like test_main_routes.py).
    """
    app.dependency_overrides = {}  # Clear any existing overrides
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides = {}  # Clean up after

@pytest.fixture(autouse=True)
def setup_database():
    """
    Create and drop tables for every test function.
    Ensures 'users' table exists before any request is made.
    """
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

# Initialize client
client = TestClient(app)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------
def test_access_protected_route_no_token():
    """Test accessing a protected route without a token (401)."""
    response = client.get("/calculations")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_access_protected_route_invalid_token():
    """Test accessing a protected route with a garbage token (401)."""
    response = client.get(
        "/calculations", 
        headers={"Authorization": "Bearer invalidtoken123"}
    )
    # The app raises 401 for validation errors in get_current_user
    assert response.status_code == 401 

def test_delete_calculation_invalid_uuid():
    """Test deleting with invalid UUID format hits the ValueError block in main.py."""
    # 1. Register a user (Requires DB tables to exist!)
    client.post("/auth/register", json={
        "email": "del@test.com", "username": "deluser", 
        "password": "SecurePass123!", "confirm_password": "SecurePass123!",
        "first_name": "Del", "last_name": "User"
    })
    
    # 2. Login
    login_res = client.post(
        "/auth/login", 
        json={"username": "deluser", "password": "SecurePass123!"}
    )
    token = login_res.json()["access_token"]
    
    # 3. Send Request with Invalid UUID
    response = client.delete(
        "/calculations/not-a-uuid", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    assert "Invalid calculation id" in response.json()["detail"]

def test_update_calculation_invalid_uuid():
    """Test updating with invalid UUID format."""
    # 1. Register
    client.post("/auth/register", json={
        "email": "upd@test.com", "username": "upduser", 
        "password": "SecurePass123!", "confirm_password": "SecurePass123!",
        "first_name": "Upd", "last_name": "User"
    })

    # 2. Login
    login_res = client.post(
        "/auth/login", 
        json={"username": "upduser", "password": "SecurePass123!"}
    )
    token = login_res.json()["access_token"]
    
    # 3. Send Request
    response = client.put(
        "/calculations/not-a-uuid", 
        headers={"Authorization": f"Bearer {token}"},
        json={"inputs": [1, 2]}
    )
    assert response.status_code == 400
    assert "Invalid calculation id" in response.json()["detail"]