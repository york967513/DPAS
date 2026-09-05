from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0821CacheUser"
PASSWORD = "DPAS_Test_Password_2026!"

client = TestClient(app)

failures = 0
token = None


def cleanup():
    global token

    if token:
        try:
            logout(token)
        except Exception:
            pass

    token = None

    try:
        delete_user(TEST_USER)
    except Exception:
        pass


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def expect_status(label, response, expected):
    if response.status_code == expected:
        pass_check(
            f"{label} -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            label,
            f"expected HTTP {expected}, got HTTP {response.status_code}"
        )


def check_no_store(label, response):
    value = response.headers.get("Cache-Control", "")

    directives = {
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    }

    if "no-store" in directives:
        pass_check(
            f"{label}: Cache-Control contains no-store"
        )
    else:
        fail_check(
            label,
            f"Cache-Control does not contain no-store: {value!r}"
        )


def check_not_public_cacheable(label, response):
    value = response.headers.get("Cache-Control", "").lower()

    if "public" in value:
        fail_check(
            label,
            f"Cache-Control explicitly allows public caching: {value!r}"
        )
    else:
        pass_check(
            f"{label}: response is not marked public"
        )


def check_vary_authorization(label, response):
    cache_control = response.headers.get(
        "Cache-Control",
        ""
    ).lower()

    if "no-store" in cache_control:
        pass_check(
            f"{label}: Vary: Authorization is not required because no-store is enforced"
        )
    else:
        fail_check(
            label,
            "Vary: Authorization would be insufficient without no-store"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.21 HTTP CACHE SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated cache-security test user")

    cleanup()

    register_user(
        TEST_USER,
        PASSWORD
    )

    token = create_user_session(TEST_USER)

    if token:
        pass_check("Test session created")
    else:
        fail_check(
            "Test session creation",
            "session token was not created"
        )

    auth_headers = {
        "Authorization": f"Bearer {token}"
    }


    # ============================================================
    # 1. AUTHENTICATED SESSION RESPONSE
    # ============================================================

    print()
    print("[1] AUTHENTICATED SESSION RESPONSE")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    expect_status(
        "GET /session",
        response,
        200
    )

    check_no_store(
        "GET /session",
        response
    )

    check_not_public_cacheable(
        "GET /session",
        response
    )

    check_vary_authorization(
        "GET /session",
        response
    )


    # ============================================================
    # 2. PROTECTED PROFILE RESPONSE
    # ============================================================

    print()
    print("[2] PROTECTED PROFILE RESPONSE")

    response = client.get(
        "/protected/profile",
        headers=auth_headers
    )

    expect_status(
        "GET /protected/profile",
        response,
        200
    )

    check_no_store(
        "GET /protected/profile",
        response
    )

    check_not_public_cacheable(
        "GET /protected/profile",
        response
    )

    check_vary_authorization(
        "GET /protected/profile",
        response
    )


    # ============================================================
    # 3. PROTECTED READ RESPONSE
    # ============================================================

    print()
    print("[3] PROTECTED PROFILE READ")

    response = client.get(
        "/protected/profile/read",
        headers=auth_headers
    )

    # The isolated test user may not have profile.read.
    # Cache requirements still apply to the protected response.
    if response.status_code in (200, 403):
        pass_check(
            f"GET /protected/profile/read reached authorization -> "
            f"HTTP {response.status_code}"
        )
    else:
        fail_check(
            "GET /protected/profile/read",
            f"unexpected HTTP {response.status_code}"
        )

    check_no_store(
        "GET /protected/profile/read",
        response
    )

    check_not_public_cacheable(
        "GET /protected/profile/read",
        response
    )

    check_vary_authorization(
        "GET /protected/profile/read",
        response
    )


    # ============================================================
    # 4. ADMIN RESPONSE / AUTHORIZATION FAILURE
    # ============================================================

    print()
    print("[4] ADMIN ENDPOINT / DENIED RESPONSE")

    response = client.get(
        "/admin/users",
        headers=auth_headers
    )

    expect_status(
        "Normal user -> GET /admin/users",
        response,
        403
    )

    check_no_store(
        "Denied admin response",
        response
    )

    check_not_public_cacheable(
        "Denied admin response",
        response
    )


    # ============================================================
    # 5. UNAUTHENTICATED PROTECTED RESPONSE
    # ============================================================

    print()
    print("[5] UNAUTHENTICATED PROTECTED RESPONSE")

    response = client.get(
        "/session"
    )

    expect_status(
        "GET /session without Authorization",
        response,
        401
    )

    check_no_store(
        "Unauthenticated /session response",
        response
    )

    check_not_public_cacheable(
        "Unauthenticated /session response",
        response
    )


    # ============================================================
    # 6. LOGIN RESPONSE
    # ============================================================

    print()
    print("[6] LOGIN RESPONSE")

    response = client.post(
        "/login",
        json={
            "username": "V0821UnknownUser",
            "password": "wrong"
        }
    )

    expect_status(
        "Failed POST /login",
        response,
        401
    )

    check_no_store(
        "Failed login response",
        response
    )

    check_not_public_cacheable(
        "Failed login response",
        response
    )


    # ============================================================
    # 7. AUTH CHALLENGE RESPONSE
    # ============================================================

    print()
    print("[7] AUTH CHALLENGE RESPONSE")

    response = client.post(
        "/auth/challenge",
        json={
            "username": TEST_USER
        }
    )

    expect_status(
        "POST /auth/challenge",
        response,
        200
    )

    check_no_store(
        "Auth challenge response",
        response
    )

    check_not_public_cacheable(
        "Auth challenge response",
        response
    )


    # ============================================================
    # 8. PUBLIC HEALTH RESPONSE
    # ============================================================

    print()
    print("[8] PUBLIC HEALTH RESPONSE")

    response = client.get(
        "/health"
    )

    expect_status(
        "GET /health",
        response,
        200
    )

    health_cache = response.headers.get(
        "Cache-Control",
        ""
    ).lower()

    if "public" in health_cache:
        fail_check(
            "Public /health response",
            f"explicitly marked public: {health_cache!r}"
        )
    else:
        pass_check(
            "Public /health response is not explicitly public"
        )


    # ============================================================
    # 9. AUTHORIZED RESPONSE MUST NOT BE PUBLIC
    # ============================================================

    print()
    print("[9] AUTHORIZATION-BOUND RESPONSE")

    response = client.get(
        "/session",
        headers={
            **auth_headers,
            "Cache-Control": "public, max-age=3600"
        }
    )

    expect_status(
        "GET /session with client cache-control request",
        response,
        200
    )

    check_no_store(
        "Server response to cache-control manipulation",
        response
    )

    check_not_public_cacheable(
        "Server response to cache-control manipulation",
        response
    )


    # ============================================================
    # 10. CACHE HEADERS MUST NOT OVERRIDE AUTHORIZATION
    # ============================================================

    print()
    print("[10] CACHE / AUTHORIZATION BOUNDARY")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "Cache-Control": "only-if-cached",
            "Pragma": "only-if-cached"
        }
    )

    expect_status(
        "Admin endpoint with cache directives",
        response,
        403
    )

    check_not_public_cacheable(
        "Admin denial with cache directives",
        response
    )


    # ============================================================
    # 11. SECURITY HEADERS REMAIN PRESENT
    # ============================================================

    print()
    print("[11] SECURITY HEADER REGRESSION")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    expected_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'",
        "Permissions-Policy": (
            "geolocation=(), microphone=(), camera=()"
        )
    }

    for name, expected_value in expected_headers.items():

        actual = response.headers.get(name)

        if actual == expected_value:
            pass_check(
                f"{name} remains correctly configured"
            )
        else:
            fail_check(
                name,
                f"expected {expected_value!r}, got {actual!r}"
            )


finally:

    print()
    print("[CLEANUP] Removing cache-security test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.21 HTTP CACHE SECURITY TEST PASSED")
else:
    print(
        f"V0.8.21 HTTP CACHE SECURITY TEST FAILED: "
        f"{failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
