from app.session_manager import (
    validate_session,
    get_session_username
)

from app.database import (
    user_has_permission,
    record_audit_event
)


def require_auth(
    token: str
):
    """
    Validate session token.

    Returns:
        username if authenticated
        None if authentication fails
    """

    if not token:

        record_audit_event(
            event_type="AUTHENTICATION",
            action="SESSION_VALIDATE",
            result="FAILURE",
            username=None,
            resource="session",
            details="Missing session token"
        )

        return None

    if not validate_session(token):

        record_audit_event(
            event_type="AUTHENTICATION",
            action="SESSION_VALIDATE",
            result="FAILURE",
            username=None,
            resource="session",
            details="Invalid or expired session"
        )

        return None

    username = get_session_username(
        token
    )

    if username is None:

        record_audit_event(
            event_type="AUTHENTICATION",
            action="SESSION_VALIDATE",
            result="FAILURE",
            username=None,
            resource="session",
            details="Session username unavailable"
        )

        return None

    return username


def require_permission(
    token: str,
    permission: str
) -> bool:
    """
    Require a valid session and permission.
    """

    username = require_auth(
        token
    )

    if username is None:

        record_audit_event(
            event_type="AUTHORIZATION",
            action="ACCESS_CHECK",
            result="DENIED",
            username=None,
            resource=permission,
            details="Authentication required"
        )

        return False

    allowed = user_has_permission(
        username,
        permission
    )

    if allowed:

        record_audit_event(
            event_type="AUTHORIZATION",
            action="ACCESS_GRANTED",
            result="SUCCESS",
            username=username,
            resource=permission,
            details="Permission granted"
        )

        return True

    record_audit_event(
        event_type="AUTHORIZATION",
        action="ACCESS_DENIED",
        result="FAILURE",
        username=username,
        resource=permission,
        details="Permission denied"
    )

    return False


def require_user(
    token: str,
    username: str
):
    """
    Check that the authenticated session belongs
    to the requested user.
    """

    authenticated_user = require_auth(
        token
    )

    if authenticated_user is None:

        record_audit_event(
            event_type="AUTHORIZATION",
            action="USER_ACCESS",
            result="DENIED",
            username=None,
            resource=username,
            details="Authentication required"
        )

        return False

    if authenticated_user == username:

        record_audit_event(
            event_type="AUTHORIZATION",
            action="USER_ACCESS",
            result="SUCCESS",
            username=authenticated_user,
            resource=username,
            details="User access granted"
        )

        return True

    record_audit_event(
        event_type="AUTHORIZATION",
        action="USER_ACCESS",
        result="DENIED",
        username=authenticated_user,
        resource=username,
        details="Attempt to access another user"
    )

    return False
