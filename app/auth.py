from datetime import datetime, timezone, timedelta

from app.database import (
    get_user,
    record_failed_attempt,
    reset_failed_attempts,
    lock_user
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


def is_user_locked(username: str) -> bool:
    user = get_user(username)

    if user is None:
        return False

    locked_until = user[5]

    if locked_until is None:
        return False

    lock_time = datetime.fromisoformat(locked_until)

    if datetime.now(timezone.utc) < lock_time:
        return True

    reset_failed_attempts(username)

    return False


def register_auth_failure(username: str):
    user = get_user(username)

    if user is None:
        return

    failed_attempts = user[4] + 1

    record_failed_attempt(username)

    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        lock_time = (
            datetime.now(timezone.utc)
            + timedelta(minutes=LOCKOUT_MINUTES)
        )

        lock_user(
            username,
            lock_time.isoformat()
        )


def validate_password(password: str) -> bool:
    if len(password) < 12:
        return False

    return True


def register_user(username: str, password: str):

    if not username:
        return None

    if not validate_password(password):
        return None

    existing_user = get_user(username)

    if existing_user is not None:
        return None

    import secrets

    from app.password import hash_password
    from app.key_manager import (
        generate_key_pair,
        encrypt_private_key,
        get_public_key_bytes
    )
    from app.database import create_user

    password_hash = hash_password(password)

    auth_salt = secrets.token_bytes(16)

    private_key, public_key = generate_key_pair()

    encrypted_private_key = encrypt_private_key(
        private_key,
        password,
        auth_salt
    )

    public_key_bytes = get_public_key_bytes(public_key)

    create_user(
        username,
        password_hash,
        auth_salt,
        public_key_bytes
    )

    return {
        "username": username,
        "encrypted_private_key": encrypted_private_key
    }


def authenticate_user(username: str, password: str) -> bool:

    user = get_user(username)

    if user is None:
        return False

    if is_user_locked(username):
        return False

    password_hash = user[2]

    from app.password import verify_password

    if verify_password(password, password_hash):

        reset_failed_attempts(username)

        return True

    register_auth_failure(username)

    return False
