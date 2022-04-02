from passlib.context import CryptContext


PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Compare plaintext password with encoded password to identify if it is correct
    """
    return PWD_CONTEXT.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash password with the PWD_CONTEXT Schema (default bcrypt)
    """
    return PWD_CONTEXT.hash(password)
