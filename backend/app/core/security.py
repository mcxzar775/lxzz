import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type


_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")


def normalize_username(username: str) -> str:
    normalized = username.strip().lower()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "username must be 3-64 characters using letters, digits, dot, dash or underscore"
        )
    return normalized


def validate_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    if len(password) > 1024:
        raise ValueError("password is too long")
    return password


def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(validate_password(password))


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def new_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_token_matches(token: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), expected_hash)

