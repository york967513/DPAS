from fastapi import Depends, Header, HTTPException

from app.authorization import (
    require_auth,
    require_permission
)


def get_current_user(
    authorization: str | None = Header(
        default=None
    )
):
    """
    Extract and validate the current user
    from the Bearer Authorization header.
    """

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required"
        )

    if not authorization.startswith(
        "Bearer "
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required"
        )

    token = authorization[7:]

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Bearer token required"
        )

    username = require_auth(
        token
    )

    if username is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session"
        )

    return {
        "username": username,
        "token": token
    }


def require_api_permission(
    permission: str
):
    """
    Create a FastAPI dependency that requires
    a specific DPAS permission.
    """

    def checker(
        current_user: dict = Depends(
            get_current_user
        )
    ):
        if not require_permission(
            current_user["token"],
            permission
        ):
            raise HTTPException(
                status_code=403,
                detail="Permission denied"
            )

        return current_user

    return checker
