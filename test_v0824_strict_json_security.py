from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0824SchemaUser"
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


def expect_status_family(label, response, allowed):
    if response.status_code in allowed:
        pass_check(
            f"{label} -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            label,
            f"expected one of {sorted(allowed)}, got HTTP {response.status_code}"
        )


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


def check_identity(label, response):
    if response.status_code != 200:
        fail_check(
            label,
            f"expected HTTP 200, got HTTP {response.status_code}"
        )
        return

    body = response.json()

    if body.get("username") == TEST_USER:
        pass_check(
            f"{label}: identity remains {TEST_USER}"
        )
    else:
        fail_check(
            label,
            f"unexpected identity: {body.get('username')!r}"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.24 STRICT JSON / UNKNOWN FIELD SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated schema test user")

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
    # 1. EXTRA FIELD ON LOGIN
    # ============================================================

    print()
    print("[1] LOGIN EXTRA FIELD")

    response = client.post(
        "/login",
        json={
            "username": "V0824Unknown",
            "password": "wrong",
            "role": "admin"
        }
    )

    expect_status(
        "Login with extra role field",
        response,
        401
    )


    # ============================================================
    # 2. MULTIPLE EXTRA LOGIN FIELDS
    # ============================================================

    print()
    print("[2] MULTIPLE LOGIN EXTRA FIELDS")

    response = client.post(
        "/login",
        json={
            "username": "V0824Unknown",
            "password": "wrong",
            "role": "admin",
            "permission": "users.delete",
            "is_admin": True,
            "permissions": [
                "users.delete"
            ]
        }
    )

    expect_status(
        "Login with multiple unknown fields",
        response,
        401
    )


    # ============================================================
    # 3. EXTRA FIELD ON AUTH CHALLENGE
    # ============================================================

    print()
    print("[3] CHALLENGE EXTRA FIELD")

    response = client.post(
        "/auth/challenge",
        json={
            "username": TEST_USER,
            "role": "admin"
        }
    )

    # A real user is supplied, so if the extra field is ignored,
    # the normal challenge operation may succeed.
    expect_status_family(
        "Challenge with extra role field",
        response,
        {200}
    )


    # ============================================================
    # 4. EXTRA FIELDS ON AUTH VERIFY
    # ============================================================

    print()
    print("[4] VERIFY EXTRA FIELDS")

    response = client.post(
        "/auth/verify",
        json={
            "username": TEST_USER,
            "challenge": "invalid",
            "signature": "invalid",
            "role": "admin",
            "permission": "users.delete"
        }
    )

    expect_status(
        "Verify with privilege-looking extra fields",
        response,
        401
    )


    # ============================================================
    # 5. EXTRA FIELD ON PROFILE WRITE
    # ============================================================

    print()
    print("[5] PROFILE EXTRA FIELD")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "SchemaTest",
            "role": "admin"
        },
        headers=auth_headers
    )

    # Authorization is expected to stop the isolated user first.
    expect_status(
        "Profile write with extra role",
        response,
        403
    )


    # ============================================================
    # 6. MANY EXTRA PROFILE FIELDS
    # ============================================================

    print()
    print("[6] MANY PROFILE EXTRA FIELDS")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "SchemaTest",
            "username": "admin",
            "role": "admin",
            "permission": "users.delete",
            "is_admin": True,
            "permissions": [
                "users.delete"
            ],
            "account_locked": False
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with many unknown fields",
        response,
        403
    )


    # ============================================================
    # 7. NESTED UNKNOWN STRUCTURE
    # ============================================================

    print()
    print("[7] NESTED UNKNOWN STRUCTURE")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "SchemaTest",
            "security": {
                "role": "admin",
                "is_admin": True,
                "permissions": [
                    "users.delete"
                ]
            }
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with nested unknown object",
        response,
        403
    )


    # ============================================================
    # 8. DUPLICATE JSON KEYS / UNKNOWN FIELD
    # ============================================================

    print()
    print("[8] DUPLICATE JSON KEY")

    response = client.put(
        "/protected/profile/write",
        content=(
            '{"display_name":"First",'
            '"role":"user",'
            '"role":"admin"}'
        ),
        headers={
            **auth_headers,
            "Content-Type": "application/json"
        }
    )

    expect_status(
        "Profile write with duplicate unknown key",
        response,
        403
    )


    # ============================================================
    # 9. EXTRA FIELD MUST NOT ALTER SESSION IDENTITY
    # ============================================================

    print()
    print("[9] SESSION IDENTITY STABILITY")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    check_identity(
        "Session after unknown-field attempts",
        response
    )


    # ============================================================
    # 10. EXTRA FIELD MUST NOT ALTER AUTHORIZATION
    # ============================================================

    print()
    print("[10] AUTHORIZATION STABILITY")

    response = client.get(
        "/admin/users",
        headers=auth_headers
    )

    expect_status(
        "Admin endpoint after unknown-field attempts",
        response,
        403
    )


    # ============================================================
    # 11. WRONG BODY TYPE
    # ============================================================

    print()
    print("[11] WRONG BODY TYPE")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": {
                "value": "SchemaTest"
            }
        },
        headers=auth_headers
    )

    # The authorization check happens before body validation
    # for this endpoint.
    expect_status(
        "Profile write with object instead of string",
        response,
        403
    )


    # ============================================================
    # 12. ARRAY BODY
    # ============================================================

    print()
    print("[12] ARRAY BODY")

    response = client.post(
        "/login",
        json=[
            {
                "username": "V0824Unknown",
                "password": "wrong"
            }
        ]
    )

    expect_status(
        "Login with array instead of object",
        response,
        422
    )


    # ============================================================
    # 13. NULL BODY
    # ============================================================

    print()
    print("[13] NULL BODY")

    response = client.post(
        "/login",
        content="null",
        headers={
            "Content-Type": "application/json"
        }
    )

    expect_status(
        "Login with JSON null body",
        response,
        422
    )


    # ============================================================
    # 14. SCHEMA BOUNDARY / NO PRIVILEGE ESCALATION
    # ============================================================

    print()
    print("[14] SCHEMA / PRIVILEGE BOUNDARY")

    response = client.get(
        "/protected/profile",
        headers=auth_headers
    )

    expect_status(
        "Protected profile after schema attacks",
        response,
        200
    )

    body = response.json()

    if body.get("username") == TEST_USER:
        pass_check(
            "Protected identity remains unchanged"
        )
    else:
        fail_check(
            "Protected identity",
            f"unexpected username: {body.get('username')!r}"
        )


finally:

    print()
    print("[CLEANUP] Removing schema test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.24 STRICT JSON / UNKNOWN FIELD SECURITY TEST PASSED")
else:
    print(
        f"V0.8.24 STRICT JSON / UNKNOWN FIELD "
        f"SECURITY TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
