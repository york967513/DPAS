import secrets
import hashlib

from datetime import datetime, timezone, timedelta

from app.database import (
    create_session,
    get_session,
    revoke_session,
    record_audit_event
)


SESSION_TTL_MINUTES = 30


def _hash_token(
    token: str
) -> bytes:
    """
    Hash a session token before storing it.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).digest()


def create_user_session(
    username: str
) -> str:
    """
    Create a new authenticated session.

    The raw token is returned to the client.
    Only its SHA-256 hash is stored in the database.
    """

    token = secrets.token_urlsafe(32)

    now = datetime.now(
        timezone.utc
    )

    expires_at = (
        now
        + timedelta(
            minutes=SESSION_TTL_MINUTES
        )
    )

    token_hash = _hash_token(
        token
    )

    create_session(
        username,
        token_hash,
        now.isoformat(),
        expires_at.isoformat()
    )

    record_audit_event(
        event_type="ACCOUNTING",
        action="SESSION_CREATED",
        result="SUCCESS",
        username=username,
        resource="sessions",
        details="Authenticated session created"
    )

    return token


def validate_session(
    token: str
) -> bool:
    """
    Validate a session token.
    """

    if not token:
        return False

    token_hash = _hash_token(
        token
    )

    session = get_session(
        token_hash
    )

    if session is None:
        return False

    # session fields:
    # 0 = id
    # 1 = username
    # 2 = token_hash
    # 3 = created_at
    # 4 = expires_at
    # 5 = revoked

    if session[5] == 1:
        return False

    expires_at = datetime.fromisoformat(
        session[4]
    )

    now = datetime.now(
        timezone.utc
    )

    if now >= expires_at:
        return False

    return True


def get_session_username(
    token: str
):
    """
    Return username associated with a valid session.
    """

    if not validate_session(token):
        return None

    token_hash = _hash_token(
        token
    )

    session = get_session(
        token_hash
    )

    if session is None:
        return None

    return session[1]


def logout(
    token: str
) -> bool:
    """
    Revoke an active session.
    """

    if not token:
        return False

    token_hash = _hash_token(
        token
    )

    session = get_session(
        token_hash
    )

    if session is None:
        return False

    username = session[1]

    if session[5] == 1:

        record_audit_event(
            event_type="ACCOUNTING",
            action="LOGOUT",
            result="FAILURE",
            username=username,
            resource="logout",
            details="Session already revoked"
        )

        return False

    result = revoke_session(
        token_hash
    )

    if result:

        record_audit_event(
            event_type="ACCOUNTING",
            action="LOGOUT",
            result="SUCCESS",
            username=username,
            resource="logout",
            details="Session revoked"
        )

    else:

        record_audit_event(
            event_type="ACCOUNTING",
            action="LOGOUT",
            result="FAILURE",
            username=username,
            resource="logout",
            details="Session revocation failed"
        )

    return result
