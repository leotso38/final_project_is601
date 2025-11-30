import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import your application and database utilities
from app.main import app
from app.database import Base, get_db

# ------------------------------------------------------------------------------
# Test Setup: In-Memory Database
# ------------------------------------------------------------------------------
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Create tables once for the module."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

# ------------------------------------------------------------------------------
# Tests: HTML Web Routes
# ------------------------------------------------------------------------------
def test_read_index():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

def test_login_page():
    response = client.get("/login")
    assert response.status_code == 200

def test_register_page():
    response = client.get("/register")
    assert response.status_code == 200

def test_dashboard_page():
    response = client.get("/dashboard")
    assert response.status_code == 200

# ------------------------------------------------------------------------------
# Tests: Auth Endpoints
# ------------------------------------------------------------------------------
def test_register_user():
    """Test API registration endpoint."""
    response = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!",
            "first_name": "Test",
            "last_name": "User"
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"

def test_register_existing_user():
    """Test registering a duplicate user fails."""
    response = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!",
            "first_name": "Test",
            "last_name": "User"
        },
    )
    assert response.status_code == 400

def test_login_json_success():
    """Test JSON login endpoint returns token."""
    client.post("/auth/register", json={
        "email": "login@example.com", "username": "loginuser", 
        "password": "SecurePass123!", "confirm_password": "SecurePass123!",
        "first_name": "Login", "last_name": "User"
    })
    
    response = client.post(
        "/auth/login",
        json={"username": "loginuser", "password": "SecurePass123!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_json_failure():
    """Test JSON login with wrong password."""
    response = client.post(
        "/auth/login",
        json={"username": "testuser", "password": "WrongPassword123!"}
    )
    assert response.status_code == 401

def test_login_form_success():
    """Test OAuth2 Form login."""
    client.post("/auth/register", json={
        "email": "form@example.com", "username": "formuser", 
        "password": "SecurePass123!", "confirm_password": "SecurePass123!",
        "first_name": "Form", "last_name": "User"
    })

    response = client.post(
        "/auth/token",
        data={"username": "formuser", "password": "SecurePass123!"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

# ------------------------------------------------------------------------------
# Tests: Calculations BREAD
# ------------------------------------------------------------------------------
@pytest.fixture
def auth_headers():
    """Helper fixture to get auth headers for requests."""
    client.post(
        "/auth/register",
        json={
            "email": "calc@example.com",
            "username": "calcuser",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!",
            "first_name": "Calc",
            "last_name": "User"
        },
    )
    response = client.post(
        "/auth/login",
        json={"username": "calcuser", "password": "SecurePass123!"}
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_create_calculation(auth_headers):
    """Test creating a new calculation."""
    # FIX: Changed inputs from dict to list to match schema
    response = client.post(
        "/calculations",
        headers=auth_headers,
        json={
            "type": "addition",
            "inputs": [10, 5] 
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["inputs"] == [10.0, 5.0]
    assert data["result"] == 15.0

def test_list_calculations(auth_headers):
    """Test listing calculations."""
    response = client.get("/calculations", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_get_calculation_by_id(auth_headers):
    """Test retrieving a specific calculation."""
    # FIX: Changed inputs from dict to list
    create_res = client.post(
        "/calculations",
        headers=auth_headers,
        json={"type": "subtraction", "inputs": [10, 5]}
    )
    # This should now succeed and have an 'id'
    calc_id = create_res.json()["id"]

    response = client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["id"] == calc_id

    # Test Web Route View
    web_response = client.get(f"/dashboard/view/{calc_id}")
    assert web_response.status_code == 200

def test_update_calculation(auth_headers):
    """Test updating a calculation."""
    # FIX: Changed inputs from dict to list
    create_res = client.post(
        "/calculations",
        headers=auth_headers,
        json={"type": "multiplication", "inputs": [2, 3]}
    )
    calc_id = create_res.json()["id"]
    
    # FIX: Update with list
    response = client.put(
        f"/calculations/{calc_id}",
        headers=auth_headers,
        json={"inputs": [3, 3]}
    )
    assert response.status_code == 200
    # 3 * 3 = 9.0
    assert response.json()["result"] == 9.0

    # Test Web Route Edit
    web_response = client.get(f"/dashboard/edit/{calc_id}")
    assert web_response.status_code == 200

def test_delete_calculation(auth_headers):
    """Test deleting a calculation."""
    # FIX: Changed inputs from dict to list
    create_res = client.post(
        "/calculations",
        headers=auth_headers,
        json={"type": "division", "inputs": [10, 2]}
    )
    calc_id = create_res.json()["id"]

    response = client.delete(f"/calculations/{calc_id}", headers=auth_headers)
    assert response.status_code == 204

    get_res = client.get(f"/calculations/{calc_id}", headers=auth_headers)
    assert get_res.status_code == 404

def test_get_calculation_invalid_id(auth_headers):
    response = client.get("/calculations/invalid-uuid", headers=auth_headers)
    assert response.status_code == 400

def test_get_calculation_not_found(auth_headers):
    response = client.get("/calculations/00000000-0000-0000-0000-000000000000", headers=auth_headers)
    assert response.status_code == 404

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200