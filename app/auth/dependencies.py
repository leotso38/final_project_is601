from datetime import datetime
from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.user import UserResponse
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency to get the current user by decoding the token 
    and fetching the real record from the database.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Decode the token to get the ID (sub)
    token_data = User.verify_token(token)
    if token_data is None:
        raise credentials_exception

    user_id = None

    try:
        # Handle different payload formats (dict vs UUID)
        if isinstance(token_data, dict):
            user_id = token_data.get("sub")
        elif isinstance(token_data, UUID):
            user_id = token_data
        
        if user_id is None:
            raise credentials_exception

        # 2. QUERY THE DATABASE (The Fix)
        # We use the ID to find the actual user record
        user = db.query(User).filter(User.id == user_id).first()
        
        if user is None:
            raise credentials_exception
            
        return user

    except Exception:
        raise credentials_exception

def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to ensure that the current user is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user