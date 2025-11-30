from passlib.context import CryptContext
import bcrypt
import passlib.handlers.bcrypt

# --- FIX 1: Patch bcrypt for passlib compatibility ---
# Passlib 1.7.4 relies on bcrypt.__about__ which was removed in bcrypt 4.0.0
# This prevents the "AttributeError: module 'bcrypt' has no attribute '__about__'"
if not hasattr(bcrypt, "__about__"):
    class About:
        __version__ = bcrypt.__version__
    bcrypt.__about__ = About()

# --- FIX 2: Disable passlib's bcrypt wrap bug detection ---
# Passlib sends a >72 byte string to check for a legacy bug.
# Bcrypt 4.0+ raises ValueError for strings >72 bytes, causing this check to crash.
# We disable the check as modern bcrypt implementations don't have this bug.
passlib.handlers.bcrypt.detect_wrap_bug = lambda ident: False

# Setup password hashing context (using bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Generates a hash from a plain password.
    """
    return pwd_context.hash(password)