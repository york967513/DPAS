from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey
)

from app.database import (
    get_user,
    save_challenge,
    invalidate_active_challenges,
    get_challenge,
    mark_challenge_used,
    record_audit_event,
    record_failed_attempt,
    reset_failed_attempts,
    lock_user
)

from app.protocol import (
    create_authentication_request,
    verify_client_response
)


CHALLENGE_TTL_SECONDS = 60

MAX_FAILED_ATTEMPTS = 5

LOCKOUT_MINUTES = 5


def _is_account_locked(
    user
) -> bool:

    locked_until = user[5]

    if locked_until is None:
        return False

    lock_time = datetime.fromisoformat(
        locked_until
    )

    now = datetime.now(
        timezone.utc
    )

    if now < lock_time:
        return True

    reset_failed_attempts(
        user[1]
    )

    return False


def _record_authentication_failure(
    username: str,
    details: str
):

    user = get_user(
        username
    )

    if user is None:
        return

    record_failed_attempt(
        username
    )

    updated_user = get_user(
        username
    )

    if updated_user is None:
        return

    failed_attempts = updated_user[4]

    if failed_attempts >= MAX_FAILED_ATTEMPTS:

        lock_time = (
            datetime.now(timezone.utc)
            + timedelta(
                minutes=LOCKOUT_MINUTES
            )
        )

        lock_user(
            username,
            lock_time.isoformat()
        )

        record_audit_event(
            event_type="AUTHENTICATION",
            action="ACCOUNT_LOCKED",
            result="FAILURE",
            username=username,
            resource="account",
            details="Account locked after maximum failed authentication attempts"
        )

    record_audit_event(
        event_type="AUTHENTICATION",
        action="LOGIN",
        result="FAILURE",
        username=username,
        resource="auth/verify",
        details=details
    )


def create_login_challenge(
    username: str
):
    """
    Create and store a fresh authentication challenge.

    Locked accounts cannot obtain new authentication challenges.
    """

    user = get_user(
        username
    )

    if user is None:

        record_audit_event(
            event_type="AUTHENTICATION",
            action="LOGIN_CHALLENGE",
            result="FAILURE",
            username=username,
            resource="auth/challenge",
            details="Unknown user"
        )

        return None

    if _is_account_locked(
        user
    ):

        record_audit_event(
            event_type="AUTHENTICATION",
            action="LOGIN_CHALLENGE",
            result="FAILURE",
            username=username,
            resource="auth/challenge",
            details="Account locked"
        )

        return None

    request = create_authentication_request(
        username
    )

    # Only one outstanding authentication challenge
    # may exist for a user at a time.
    invalidate_active_challenges(
        username
    )

    save_challenge(
        username,
        request["challenge"]
    )

    record_audit_event(
        event_type="AUTHENTICATION",
        action="LOGIN_CHALLENGE",
        result="SUCCESS",
        username=username,
        resource="auth/challenge"
    )

    return request


def verify_login_response(
    username: str,
    challenge: str,
    signature: str
) -> bool:
    """
    Verify the client's authentication signature.

    Authentication failures are counted toward account lockout.

    The challenge must:
    1. Exist
    2. Belong to the user
    3. Not have been used
    4. Not be older than CHALLENGE_TTL_SECONDS
    5. Have a valid Ed25519 signature
    """

    user = get_user(
        username
    )

    if user is None:

        record_audit_event(
            event_type="AUTHENTICATION",
            action="LOGIN",
            result="FAILURE",
            username=username,
            resource="auth/verify",
            details="Unknown user"
        )

        return False

    if _is_account_locked(
        user
    ):

        record_audit_event(
            event_type="AUTHENTICATION",
            action="LOGIN",
            result="FAILURE",
            username=username,
            resource="auth/verify",
            details="Account locked"
        )

        return False

    stored_challenge = get_challenge(
        username,
        challenge
    )

    if stored_challenge is None:

        _record_authentication_failure(
            username,
            "Invalid challenge"
        )

        return False

    if stored_challenge[4] == 1:

        _record_authentication_failure(
            username,
            "Challenge already used"
        )

        return False

    created_at = datetime.fromisoformat(
        stored_challenge[3]
    )

    now = datetime.now(
        timezone.utc
    )

    age = (
        now - created_at
    ).total_seconds()

    if age > CHALLENGE_TTL_SECONDS:

        _record_authentication_failure(
            username,
            "Challenge expired"
        )

        return False

    public_key_bytes = user[7]

    if public_key_bytes is None:

        _record_authentication_failure(
            username,
            "User has no public key"
        )

        return False

    try:

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

    except Exception:

        _record_authentication_failure(
            username,
            "Invalid public key"
        )

        return False

    valid = verify_client_response(
        public_key,
        challenge,
        signature
    )

    if not valid:

        _record_authentication_failure(
            username,
            "Invalid signature"
        )

        return False

    result = mark_challenge_used(
        username,
        challenge
    )

    if not result:

        _record_authentication_failure(
            username,
            "Challenge could not be consumed"
        )

        return False

    reset_failed_attempts(
        username
    )

    record_audit_event(
        event_type="AUTHENTICATION",
        action="LOGIN",
        result="SUCCESS",
        username=username,
        resource="auth/verify"
    )

    return True
