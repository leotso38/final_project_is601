# tests/unit/test_password_logic.py
from app.models.user import User

def test_hashed_password_setter_logic():
    """
    UNIT TEST: Logic Verification
    Verifies that the @hashed_password.setter correctly updates the 
    underlying 'password' field. This ensures the fix for the 
    'AttributeError' works in isolation.
    """
    # 1. Arrange: Create a user in memory (no DB needed)
    user = User(
        first_name="Logic",
        last_name="Test",
        email="logic@test.com",
        username="logictest",
        password="initial_hash_value"
    )

    # 2. Assert Initial State
    assert user.password == "initial_hash_value"
    assert user.hashed_password == "initial_hash_value"

    # 3. Act: Use the setter (the logic we fixed)
    new_hash = "new_updated_hash"
    user.hashed_password = new_hash

    # 4. Assert: Verify the underlying attribute changed
    assert user.password == new_hash
    assert user.hashed_password == new_hash