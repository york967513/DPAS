from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth_manager import login
from app.dependencies import (
    get_current_user,
    require_api_permission
)
from app.session_manager import (
    logout,
    create_user_session
)
from app.server_auth import (
    create_login_challenge,
    verify_login_response
)
from app.database import (
    get_all_users,
    delete_user
)


app = FastAPI(
    title="DPAS",
    version="0.9.2"
)


# ========================================
# GLOBAL INTERNAL ERROR HANDLER
# ========================================

@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception
):
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal Server Error"
        },
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'",
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=()"
            )
        }
    )


# ========================================
# SECURITY HEADERS
# ========================================

@app.middleware("http")
async def security_headers_middleware(
    request,
    call_next
):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )

    return response


# ========================================
# REQUEST MODELS
# ========================================

class LoginRequest(BaseModel):
    username: str
    password: str


class ChallengeRequest(BaseModel):
    username: str


class VerifyRequest(BaseModel):
    username: str
    challenge: str
    signature: str


class ProfileWriteRequest(BaseModel):
    display_name: str


# ========================================
# HEALTH CHECK
# ========================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "service": "DPAS",
        "version": "0.9.2"
    }


# ========================================
# LOGIN
# ========================================

@app.post("/login")
def api_login(
    request: LoginRequest
):

    token = login(
        request.username,
        request.password
    )

    if token is None:

        raise HTTPException(
            status_code=401,
            detail="Authentication failed"
        )

    return {
        "authenticated": True,
        "token": token
    }


# ========================================
# AUTH CHALLENGE
# ========================================

@app.post("/auth/challenge")
def api_auth_challenge(
    request: ChallengeRequest
):

    challenge = create_login_challenge(
        request.username
    )

    if challenge is None:

        raise HTTPException(
            status_code=401,
            detail="Unknown user"
        )

    return challenge


# ========================================
# AUTH VERIFY
# ========================================

@app.post("/auth/verify")
def api_auth_verify(
    request: VerifyRequest
):

    valid = verify_login_response(
        request.username,
        request.challenge,
        request.signature
    )

    if not valid:

        raise HTTPException(
            status_code=401,
            detail="Authentication failed"
        )

    token = create_user_session(
        request.username
    )

    return {
        "authenticated": True,
        "token": token
    }


# ========================================
# SESSION
# ========================================

@app.get("/session")
def api_session(
    current_user: dict = Depends(
        get_current_user
    )
):

    return {
        "authenticated": True,
        "username": current_user["username"]
    }


# ========================================
# PROTECTED PROFILE
# ========================================

@app.get("/protected/profile")
def protected_profile(
    current_user: dict = Depends(
        get_current_user
    )
):

    return {
        "authenticated": True,
        "username": current_user["username"],
        "resource": "profile",
        "access": "granted"
    }


# ========================================
# PROFILE READ
# ========================================

@app.get("/protected/profile/read")
def protected_profile_read(
    current_user: dict = Depends(
        require_api_permission(
            "profile.read"
        )
    )
):

    return {
        "authenticated": True,
        "username": current_user["username"],
        "permission": "profile.read",
        "access": "granted"
    }


# ========================================
# PROFILE WRITE
# ========================================

@app.put("/protected/profile/write")
def protected_profile_write(
    request: ProfileWriteRequest,
    current_user: dict = Depends(
        require_api_permission(
            "profile.write"
        )
    )
):

    return {
        "authenticated": True,
        "username": current_user["username"],
        "permission": "profile.write",
        "access": "granted",
        "display_name": request.display_name
    }


# ========================================
# ADMIN — LIST USERS
# ========================================

@app.get("/admin/users")
def admin_users_list(
    current_user: dict = Depends(
        require_api_permission(
            "users.read"
        )
    )
):

    users = get_all_users()

    return {
        "access": "granted",
        "permission": "users.read",
        "users": [
            {
                "id": user[0],
                "username": user[1],
                "created_at": user[2],
                "failed_attempts": user[3],
                "locked_until": user[4]
            }
            for user in users
        ]
    }


# ========================================
# ADMIN — DELETE USER
# ========================================

@app.delete("/admin/users/{username}")
def admin_delete_user(
    username: str,
    current_user: dict = Depends(
        require_api_permission(
            "users.delete"
        )
    )
):

    if not delete_user(username):

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "access": "granted",
        "permission": "users.delete",
        "deleted": True,
        "username": username
    }


# ========================================
# LEGACY ADMIN DELETE
# ========================================

@app.delete("/protected/users")
def protected_users_delete(
    current_user: dict = Depends(
        require_api_permission(
            "users.delete"
        )
    )
):

    return {
        "authenticated": True,
        "username": current_user["username"],
        "permission": "users.delete",
        "access": "granted"
    }


# ========================================
# LOGOUT
# ========================================

@app.post("/logout")
def api_logout(
    current_user: dict = Depends(
        get_current_user
    )
):

    result = logout(
        current_user["token"]
    )

    if not result:

        raise HTTPException(
            status_code=401,
            detail="Invalid session"
        )

    return {
        "logged_out": True
    }
