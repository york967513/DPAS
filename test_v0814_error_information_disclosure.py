from fastapi.testclient import TestClient

import app.api as api_module

from app.api import app
from app.auth import register_user
from app.database import (
    get_connection,
    delete_user,
)
from app.session_manager import (
    create_user_session,
    logout,
)


TEST_USER = "V0814ErrorTest"
TEST_PASSWORD = "DPAS_Test_Password_2026!"


print("=" * 70)
print("DPAS V0.8.14 ERROR HANDLING / INFORMATION DISCLOSURE TEST")
print("=" * 70)

failures = 0
token = None

# Do not let TestClient re-raise an intentional server exception.
client = TestClient(
    app,
    raise_server_exceptions=False
)


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


def check_no_sensitive_disclosure(label, response):
    global failures

    body = response.text

    forbidden_fragments = [
        "Traceback",
        "File \"",
        "C:\\",
        "D:\\",
        "/home/",
        "/usr/",
        "sqlite3.",
        "OperationalError",
        "ProgrammingError",
        "IntegrityError",
        "Exception",
        "password_hash",
        "auth_salt",
        "private_key",
        "secret_key",
        "DPAS_Test_Password_2026!",
    ]

    found = [
        fragment
        for fragment in forbidden_fragments
        if fragment.lower() in body.lower()
    ]

    if not found:
        print(
            f"[PASS] {label} contains no tested sensitive "
            f"information-disclosure fragments"
        )
    else:
        print(
            f"[FAIL] {label} exposes sensitive/internal data: "
            f"{found}"
        )
        failures += 1


def check_generic_500(label, response):
    global failures

    if response.status_code == 500:
        print(
            f"[PASS] {label} returned HTTP 500"
        )
    else:
        print(
            f"[FAIL] {label} expected HTTP 500, "
            f"got HTTP {response.status_code}"
        )
        failures += 1


try:

    # ============================================================
    # SETUP
    # ============================================================

    print()
    print("[SETUP] Creating isolated error-handling test user")

    cleanup()

    register_user(
        TEST_USER,
        TEST_PASSWORD
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        (TEST_USER,)
    )
    user_row = cursor.fetchone()

    cursor.execute(
        "SELECT id FROM roles WHERE name = 'admin'"
    )
    role_row = cursor.fetchone()

    if not user_row or not role_row:
        raise RuntimeError(
            "Could not resolve test user or admin role"
        )

    cursor.execute(
        """
        INSERT INTO user_roles (user_id, role_id)
        VALUES (?, ?)
        """,
        (user_row[0], role_row[0])
    )

    connection.commit()
    connection.close()

    token = create_user_session(TEST_USER)

    if token:
        print("[PASS] Authenticated error-test session created")
    else:
        print("[FAIL] Could not create error-test session")
        failures += 1

    auth_headers = {
        "Authorization": f"Bearer {token}"
    }


    # ============================================================
    # 1. NORMAL AUTHENTICATION ERROR
    # ============================================================

    print()
    print("[1] GENERIC AUTHENTICATION ERROR")

    response = client.post(
        "/login",
        json={
            "username": "V0814UnknownUser",
            "password": "wrong-password"
        }
    )

    if response.status_code == 401:
        print("[PASS] Invalid login returned HTTP 401")
    else:
        print(
            f"[FAIL] Invalid login returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    if response.text == '{"detail":"Authentication failed"}':
        print("[PASS] Invalid login uses generic error detail")
    else:
        print(
            f"[FAIL] Unexpected authentication error body: "
            f"{response.text}"
        )
        failures += 1

    check_no_sensitive_disclosure(
        "Invalid login response",
        response
    )


    # ============================================================
    # 2. INVALID SESSION ERROR
    # ============================================================

    print()
    print("[2] INVALID SESSION ERROR")

    response = client.get(
        "/session",
        headers={
            "Authorization": "Bearer INVALID_V0814_TOKEN"
        }
    )

    if response.status_code == 401:
        print("[PASS] Invalid session returned HTTP 401")
    else:
        print(
            f"[FAIL] Invalid session returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    check_no_sensitive_disclosure(
        "Invalid session response",
        response
    )


    # ============================================================
    # 3. VALIDATION ERROR
    # ============================================================

    print()
    print("[3] VALIDATION ERROR")

    response = client.post(
        "/auth/verify",
        json={}
    )

    if response.status_code == 422:
        print("[PASS] Invalid request returned HTTP 422")
    else:
        print(
            f"[FAIL] Invalid request returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    try:
        body = response.json()

        if isinstance(body, dict) and "detail" in body:
            print("[PASS] Validation error has structured detail")
        else:
            print("[FAIL] Validation error has no detail field")
            failures += 1

    except Exception:
        print("[FAIL] Validation response is not valid JSON")
        failures += 1

    check_no_sensitive_disclosure(
        "Validation response",
        response
    )


    # ============================================================
    # 4. NOT FOUND ERROR
    # ============================================================

    print()
    print("[4] NOT FOUND ERROR")

    response = client.get(
        "/this-v0814-resource-does-not-exist"
    )

    if response.status_code == 404:
        print("[PASS] Unknown route returned HTTP 404")
    else:
        print(
            f"[FAIL] Unknown route returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    check_no_sensitive_disclosure(
        "404 response",
        response
    )


    # ============================================================
    # 5. METHOD NOT ALLOWED ERROR
    # ============================================================

    print()
    print("[5] METHOD NOT ALLOWED ERROR")

    response = client.get("/login")

    if response.status_code == 405:
        print("[PASS] Invalid method returned HTTP 405")
    else:
        print(
            f"[FAIL] Invalid method returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    check_no_sensitive_disclosure(
        "405 response",
        response
    )


    # ============================================================
    # 6. USER NOT FOUND ERROR
    # ============================================================

    print()
    print("[6] ADMIN USER-NOT-FOUND ERROR")

    response = client.delete(
        "/admin/users/V0814NonexistentUser",
        headers=auth_headers
    )

    if response.status_code == 404:
        print("[PASS] Missing admin target returned HTTP 404")
    else:
        print(
            f"[FAIL] Missing admin target returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    if response.text == '{"detail":"User not found"}':
        print("[PASS] Missing admin target uses controlled error detail")
    else:
        print(
            f"[FAIL] Unexpected user-not-found body: "
            f"{response.text}"
        )
        failures += 1

    check_no_sensitive_disclosure(
        "User-not-found response",
        response
    )


    # ============================================================
    # 7. INTENTIONAL INTERNAL SERVER ERROR
    # ============================================================

    print()
    print("[7] INTENTIONAL INTERNAL SERVER ERROR")

    original_get_all_users = api_module.get_all_users

    def forced_internal_error():
        raise RuntimeError(
            "V0814_INTERNAL_TEST_SECRET"
        )

    api_module.get_all_users = forced_internal_error

    try:
        response = client.get(
            "/admin/users",
            headers=auth_headers
        )
    finally:
        api_module.get_all_users = original_get_all_users

    check_generic_500(
        "Forced internal exception",
        response
    )

    try:
        error_body = response.json()
    except Exception:
        error_body = None

    if (
        isinstance(error_body, dict)
        and error_body.get("detail") == "Internal Server Error"
        and len(error_body) == 1
    ):
        print("[PASS] 500 response uses generic JSON error body")
    else:
        print(
            f"[FAIL] 500 response is not generic: "
            f"{response.text}"
        )
        failures += 1

    if "V0814_INTERNAL_TEST_SECRET" not in response.text:
        print("[PASS] Internal exception message not disclosed")
    else:
        print("[FAIL] Internal exception message disclosed")
        failures += 1

    check_no_sensitive_disclosure(
        "500 response",
        response
    )


    # ============================================================
    # 8. SECURITY HEADERS ALSO PRESENT ON 500
    # ============================================================

    print()
    print("[8] SECURITY HEADERS ON INTERNAL ERROR")

    expected_headers = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "content-security-policy": "default-src 'none'",
        "permissions-policy": (
            "geolocation=(), microphone=(), camera=()"
        ),
    }

    for header_name, expected_value in expected_headers.items():

        actual_value = response.headers.get(
            header_name
        )

        if actual_value == expected_value:
            print(
                f"[PASS] {header_name}: {actual_value}"
            )
        else:
            print(
                f"[FAIL] {header_name}: "
                f"expected '{expected_value}', "
                f"got '{actual_value}'"
            )
            failures += 1


    # ============================================================
    # 9. INTERNAL ERROR DOES NOT BREAK APPLICATION
    # ============================================================

    print()
    print("[9] POST-ERROR APPLICATION RECOVERY")

    response = client.get(
        "/health"
    )

    if response.status_code == 200:
        print(
            "[PASS] Application remained operational "
            "after internal exception"
        )
    else:
        print(
            f"[FAIL] Application health check returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    if response.json().get("status") == "ok":
        print("[PASS] Health response remained valid")
    else:
        print("[FAIL] Health response is invalid")
        failures += 1


finally:

    print()
    print("[CLEANUP] Removing error-test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.14 ERROR HANDLING / INFORMATION DISCLOSURE TEST PASSED")
else:
    print(
        f"V0.8.14 ERROR HANDLING / INFORMATION DISCLOSURE "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
