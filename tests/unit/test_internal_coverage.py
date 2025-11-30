import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.auth.dependencies import get_current_active_user  # Import the dependency function

# Initialize client
client = TestClient(app)

# ------------------------------------------------------------------------------
# 1. Test the Lifespan (Startup) Event
# ------------------------------------------------------------------------------
def test_lifespan_startup_event():
    """
    Test that the lifespan event triggers table creation.
    
    Using 'with TestClient(app)' triggers the startup/shutdown lifespan events
    automatically, avoiding the need for complex async/trio configuration.
    """
    # Mock the engine/metadata to avoid actual DB ops during this unit test
    with patch("app.main.Base.metadata.create_all") as mock_create:
        # entering the context manager triggers the startup event
        with TestClient(app) as c:
            pass  
        
        # Verify create_all was called
        mock_create.assert_called()

# ------------------------------------------------------------------------------
# 2. Test Database Rollbacks (Error Handling)
# ------------------------------------------------------------------------------
def test_register_user_rollback():
    """
    Mock User.register to raise a ValueError.
    This forces the 'except ValueError' block in main.py to run,
    triggering db.rollback().
    """
    payload = {
        "email": "rollback@test.com", 
        "username": "rbuser", 
        "password": "SecurePass123!", 
        "confirm_password": "SecurePass123!",
        "first_name": "Rb", 
        "last_name": "User"
    }

    # Mock User.register to fail
    with patch("app.models.user.User.register", side_effect=ValueError("Forced DB Error")):
        response = client.post("/auth/register", json=payload)
        
    assert response.status_code == 400
    assert "Forced DB Error" in response.json()["detail"]

def test_create_calculation_rollback():
    """
    Mock Calculation.create to raise a ValueError.
    This forces the 'except ValueError' block in the calculation creation 
    endpoint to run, triggering db.rollback().
    """
    # 1. Create a dummy user object
    mock_user = MagicMock()
    mock_user.id = "123e4567-e89b-12d3-a456-426614174000"
    
    # FIX: Use the actual function object as the key, NOT a string
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    
    try:
        # 2. Mock Calculation.create to fail
        with patch("app.models.calculation.Calculation.create", side_effect=ValueError("Calc Error")):
            response = client.post(
                "/calculations",
                json={"type": "addition", "inputs": [1, 2]}
            )
            
        assert response.status_code == 400
        assert "Calc Error" in response.json()["detail"]
    finally:
        # Clean up overrides
        app.dependency_overrides = {}

# ------------------------------------------------------------------------------
# 3. Test Models __repr__ (Bonus Coverage)
# ------------------------------------------------------------------------------
def test_model_reprs():
    from app.models.user import User
    from app.models.calculation import Calculation
    from uuid import uuid4
    
    u = User(id=uuid4(), username="test", email="test@test.com")
    c = Calculation(id=uuid4(), type="addition", inputs=[1, 2], result=3)
    
    # Trigger __repr__ if it exists to ensure lines are covered
    str(u)
    repr(u)
    str(c)
    repr(c)