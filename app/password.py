from argon2 import PasswordHasher
from argon2.low_level import (
    hash_secret_raw,
    Type
)

from argon2.exceptions import VerifyMismatchError


password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)

    except VerifyMismatchError:
        return False


def derive_key(
    password: str,
    salt: bytes,
    length: int = 32
) -> bytes:

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=length,
        type=Type.ID
    )