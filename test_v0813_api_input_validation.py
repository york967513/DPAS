from fastapi.testclient import TestClient

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


TEST_USER = "V0813ValidationUser"
TEST_PASSWORD = "DPAS_Test_Password_2026!"


print("=" * 70)
print("DPAS V0.8.13 API INPUT VALIDATION / MALFORMED REQUEST TEST")
print("=" * 70)

client = TestClient(app)

failures = 0
token = None


def expect_status(label, response, expected):
    global failures

    if response.status_code == expected:
        print(
            f"[PASS] {label} -> HTTP {response.status_code}"
        )
    else:
        print(
            f"[FAIL] {label} -> expected HTTP {expected}, "
            f"got HTTP {response.status_code}"
        )
        failures += 1


def expect_detail(label, response):
    global failures

    try:
        body = response.json()
    except Exception:
        print(
            f"[FAIL] {label} -> response is not valid JSON"
        )
        failures += 1
        return

    if isinstance(body, dict) and "detail" in body:
        print(
            f"[PASS] {label} -> JSON validation detail present"
        )
    else:
        print(
            f"[FAIL] {label} -> JSON validation detail missing"
        )
        failures += 1


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


try:

    # ============================================================
    # SETUP
    # ============================================================

    print()
    print("[SETUP] Creating authenticated validation test user")

    cleanup()

    register_user(
        TEST_USER,
        TEST_PASSWORD
    )

    # Give the isolated test user the admin role so that
    # profile.write permission is definitely available.
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
        print("[PASS] Authenticated validation session created")
    else:
        print("[FAIL] Could not create validation session")
        failures += 1

    auth_headers = {
        "Authorization": f"Bearer {token}"
    }


    # ============================================================
    # 1. LOGIN — MISSING REQUIRED FIELD
    # ============================================================

    print()
    print("[1] LOGIN VALIDATION — MISSING FIELD")

    response = client.post(
        "/login",
        json={
            "username": "V0813User"
        }
    )

    expect_status(
        "POST /login without password",
        response,
        422
    )

    expect_detail(
        "POST /login without password",
        response
    )


    # ============================================================
    # 2. LOGIN — WRONG FIELD TYPE
    # ============================================================

    print()
    print("[2] LOGIN VALIDATION — WRONG TYPE")

    response = client.post(
        "/login",
        json={
            "username": 12345,
            "password": "dummy"
        }
    )

    expect_status(
        "POST /login with numeric username",
        response,
        422
    )

    expect_detail(
        "POST /login with numeric username",
        response
    )


    # ============================================================
    # 3. AUTH CHALLENGE — MISSING FIELD
    # ============================================================

    print()
    print("[3] CHALLENGE VALIDATION — MISSING FIELD")

    response = client.post(
        "/auth/challenge",
        json={}
    )

    expect_status(
        "POST /auth/challenge with empty JSON",
        response,
        422
    )

    expect_detail(
        "POST /auth/challenge with empty JSON",
        response
    )


    # ============================================================
    # 4. AUTH CHALLENGE — WRONG FIELD TYPE
    # ============================================================

    print()
    print("[4] CHALLENGE VALIDATION — WRONG TYPE")

    response = client.post(
        "/auth/challenge",
        json={
            "username": {
                "unexpected": "object"
            }
        }
    )

    expect_status(
        "POST /auth/challenge with object username",
        response,
        422
    )

    expect_detail(
        "POST /auth/challenge with object username",
        response
    )


    # ============================================================
    # 5. AUTH VERIFY — MISSING FIELDS
    # ============================================================

    print()
    print("[5] VERIFY VALIDATION — MISSING FIELDS")

    response = client.post(
        "/auth/verify",
        json={}
    )

    expect_status(
        "POST /auth/verify with empty JSON",
        response,
        422
    )

    expect_detail(
        "POST /auth/verify with empty JSON",
        response
    )


    # ============================================================
    # 6. AUTH VERIFY — WRONG FIELD TYPES
    # ============================================================

    print()
    print("[6] VERIFY VALIDATION — WRONG TYPES")

    response = client.post(
        "/auth/verify",
        json={
            "username": ["V0813User"],
            "challenge": 12345,
            "signature": {
                "not": "a string"
            }
        }
    )

    expect_status(
        "POST /auth/verify with incompatible field types",
        response,
        422
    )

    expect_detail(
        "POST /auth/verify with incompatible field types",
        response
    )


    # ============================================================
    # 7. PROFILE WRITE — MISSING BODY
    # ============================================================

    print()
    print("[7] PROFILE WRITE VALIDATION — MISSING BODY")

    response = client.put(
        "/protected/profile/write",
        headers=auth_headers
    )

    expect_status(
        "PUT /protected/profile/write without body",
        response,
        422
    )

    expect_detail(
        "PUT /protected/profile/write without body",
        response
    )


    # ============================================================
    # 8. PROFILE WRITE — MISSING FIELD
    # ============================================================

    print()
    print("[8] PROFILE WRITE VALIDATION — MISSING FIELD")

    response = client.put(
        "/protected/profile/write",
        json={},
        headers=auth_headers
    )

    expect_status(
        "PUT /protected/profile/write with empty JSON",
        response,
        422
    )

    expect_detail(
        "PUT /protected/profile/write with empty JSON",
        response
    )


    # ============================================================
    # 9. PROFILE WRITE — WRONG FIELD TYPE
    # ============================================================

    print()
    print("[9] PROFILE WRITE VALIDATION — WRONG TYPE")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": 987654
        },
        headers=auth_headers
    )

    expect_status(
        "PUT /protected/profile/write with numeric display_name",
        response,
        422
    )

    expect_detail(
        "PUT /protected/profile/write with numeric display_name",
        response
    )


    # ============================================================
    # 10. MALFORMED JSON BODY
    # ============================================================

    print()
    print("[10] MALFORMED JSON")

    response = client.post(
        "/login",
        content='{"username":"broken","password":',
        headers={
            "Content-Type": "application/json"
        }
    )

    expect_status(
        "POST /login with malformed JSON",
        response,
        422
    )

    expect_detail(
        "POST /login with malformed JSON",
        response
    )


    # ============================================================
    # 11. WRONG CONTENT TYPE
    # ============================================================

    print()
    print("[11] WRONG CONTENT TYPE")

    response = client.post(
        "/login",
        content="username=test&password=test",
        headers={
            "Content-Type": "text/plain"
        }
    )

    expect_status(
        "POST /login with text/plain body",
        response,
        422
    )

    expect_detail(
        "POST /login with text/plain body",
        response
    )


    # ============================================================
    # 12. HTTP METHOD VALIDATION
    # ============================================================

    print()
    print("[12] HTTP METHOD VALIDATION")

    method_tests = [
        (
            "GET /login",
            lambda: client.get("/login")
        ),
        (
            "GET /auth/challenge",
            lambda: client.get("/auth/challenge")
        ),
        (
            "GET /auth/verify",
            lambda: client.get("/auth/verify")
        ),
        (
            "POST /protected/profile/write",
            lambda: client.post(
                "/protected/profile/write",
                headers=auth_headers
            )
        ),
        (
            "PUT /session",
            lambda: client.put(
                "/session",
                headers=auth_headers
            )
        ),
        (
            "DELETE /health",
            lambda: client.delete("/health")
        ),
    ]

    for label, request_fn in method_tests:

        response = request_fn()

        expect_status(
            label,
            response,
            405
        )


    # ============================================================
    # 13. UNKNOWN ROUTE
    # ============================================================

    print()
    print("[13] UNKNOWN ROUTE")

    response = client.post(
        "/this-api-route-does-not-exist",
        json={}
    )

    expect_status(
        "POST unknown API route",
        response,
        404
    )


    # ============================================================
    # 14. VALID REQUEST SHAPES MUST REACH APPLICATION LAYER
    # ============================================================

    print()
    print("[14] VALID REQUEST SHAPES ARE NOT REJECTED BY SCHEMA")

    response = client.post(
        "/login",
        json={
            "username": "V0813Nonexistent",
            "password": "DPAS_Test_Password_2026!"
        }
    )

    expect_status(
        "POST /login with valid schema",
        response,
        401
    )

    if response.status_code == 401:
        print(
            "[PASS] Valid login schema reached authentication layer"
        )
    else:
        print(
            "[FAIL] Valid login schema was rejected before "
            "authentication layer"
        )
        failures += 1


finally:

    print()
    print("[CLEANUP] Removing validation test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.13 API INPUT VALIDATION TEST PASSED")
else:
    print(
        f"V0.8.13 API INPUT VALIDATION TEST FAILED: "
        f"{failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
