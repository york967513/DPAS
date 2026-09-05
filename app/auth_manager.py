from app.database import get_user

from app.server_auth import (
    create_login_challenge,
    verify_login_response
)

from app.client_auth import (
    create_client_signature
)

from app.session_manager import (
    create_user_session
)

from app.auth import (
    is_user_locked
)


def login(username: str, password: str):

    user = get_user(username)

    if user is None:
        return None

    if is_user_locked(username):
        return None

    auth_salt = user[6]

    if auth_salt is None:
        return None

    request = create_login_challenge(username)

    if request is None:
        return None

    challenge = request["challenge"]

    try:

        signature = create_client_signature(
            username,
            password,
            auth_salt,
            challenge
        )

    except Exception:

        from app.auth import register_auth_failure

        register_auth_failure(username)

        return None

    authenticated = verify_login_response(
        username,
        challenge,
        signature
    )

    if not authenticated:
        return None

    return create_user_session(username)
