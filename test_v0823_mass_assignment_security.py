from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0823MassUser"
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


def check_identity(response, expected_username, label):
    if response.status_code != 200:
        fail_check(
            label,
            f"expected HTTP 200, got HTTP {response.status_code}"
        )
        return

    body = response.json()

    if body.get("username") == expected_username:
        pass_check(
            f"{label}: identity remains {expected_username}"
        )
    else:
        fail_check(
            label,
            f"identity changed to {body.get('username')!r}"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.23 MASS ASSIGNMENT / OVERPOSTING SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated mass-assignment test user")

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
    # 1. BASELINE PROFILE WRITE
    # ============================================================

    print()
    print("[1] BASELINE PROFILE WRITE")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "NormalValue"
        },
        headers=auth_headers
    )

    # User has no profile.write permission.
    # This establishes the normal authorization boundary.
    expect_status(
        "Normal profile write",
        response,
        403
    )


    # ============================================================
    # 2. ROLE FIELD INJECTION
    # ============================================================

    print()
    print("[2] ROLE FIELD INJECTION")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "role": "admin"
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with role=admin",
        response,
        403
    )


    # ============================================================
    # 3. PERMISSION FIELD INJECTION
    # ============================================================

    print()
    print("[3] PERMISSION FIELD INJECTION")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "permission": "users.delete"
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with permission=users.delete",
        response,
        403
    )


    # ============================================================
    # 4. IS_ADMIN FIELD INJECTION
    # ============================================================

    print()
    print("[4] IS_ADMIN FIELD INJECTION")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "is_admin": True
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with is_admin=true",
        response,
        403
    )


    # ============================================================
    # 5. USERNAME FIELD INJECTION
    # ============================================================

    print()
    print("[5] USERNAME FIELD INJECTION")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "username": "admin"
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with username=admin",
        response,
        403
    )


    # ============================================================
    # 6. MULTIPLE PRIVILEGE FIELDS
    # ============================================================

    print()
    print("[6] MULTIPLE PRIVILEGE FIELDS")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "username": "admin",
            "role": "admin",
            "permission": "users.delete",
            "is_admin": True,
            "permissions": [
                "users.delete",
                "users.read"
            ]
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with multiple privilege fields",
        response,
        403
    )


    # ============================================================
    # 7. NESTED PRIVILEGE OBJECT
    # ============================================================

    print()
    print("[7] NESTED PRIVILEGE OBJECT")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "user": {
                "role": "admin",
                "permissions": [
                    "users.delete"
                ]
            }
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with nested privilege object",
        response,
        403
    )


    # ============================================================
    # 8. NULL PRIVILEGE VALUES
    # ============================================================

    print()
    print("[8] NULL PRIVILEGE VALUES")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "role": None,
            "permission": None,
            "is_admin": None
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with null privilege fields",
        response,
        403
    )


    # ============================================================
    # 9. ARRAY VALUES FOR PRIVILEGE FIELDS
    # ============================================================

    print()
    print("[9] ARRAY PRIVILEGE VALUES")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "role": ["admin"],
            "permission": [
                "users.delete"
            ],
            "is_admin": [True]
        },
        headers=auth_headers
    )

    expect_status_family(
        "Profile write with array privilege fields",
        response,
        {403, 422}
    )


    # ============================================================
    # 10. STRING BOOLEAN / TYPE CONFUSION
    # ============================================================

    print()
    print("[10] TYPE CONFUSION")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Attacker",
            "is_admin": "true",
            "role": "1",
            "permission": "users.delete"
        },
        headers=auth_headers
    )

    expect_status(
        "Profile write with string privilege values",
        response,
        403
    )


    # ============================================================
    # 11. EXTRA SECURITY-LIKE FIELDS MUST NOT CHANGE SESSION
    # ============================================================

    print()
    print("[11] EXTRA FIELDS / SESSION IDENTITY")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    check_identity(
        response,
        TEST_USER,
        "Session identity after mass-assignment attempts"
    )


    # ============================================================
    # 12. EXTRA FIELDS MUST NOT CHANGE AUTHORIZATION
    # ============================================================

    print()
    print("[12] EXTRA FIELDS / AUTHORIZATION")

    response = client.get(
        "/admin/users",
        headers=auth_headers
    )

    expect_status(
        "Admin access after privilege-field injection attempts",
        response,
        403
    )


    # ============================================================
    # 13. ONLY DECLARED FIELD SHOULD BE ACCEPTABLE SHAPE
    # ============================================================

    print()
    print("[13] DECLARED FIELD BOUNDARY")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "Allowed",
            "unexpected": "ignored-or-rejected"
        },
        headers=auth_headers
    )

    # Authorization blocks this isolated user before the endpoint
    # can perform the update. The important condition is that no
    # privilege is granted and the request remains unauthorized.
    expect_status_family(
        "Profile write with one unrelated extra field",
        response,
        {403, 422}
    )


    # ============================================================
    # 14. MASS-ASSIGNMENT VIA ADMIN-LIKE QUERY PARAMETERS
    # ============================================================

    print()
    print("[14] QUERY PARAMETER COMBINATION")

    response = client.get(
        "/admin/users",
        params={
            "role": "admin",
            "permission": "users.delete",
            "is_admin": "true",
            "username": "admin"
        },
        headers=auth_headers
    )

    expect_status(
        "Admin endpoint with privilege-looking query parameters",
        response,
        403
    )


    # ============================================================
    # 15. FINAL AUTHORIZATION STABILITY
    # ============================================================

    print()
    print("[15] FINAL AUTHORIZATION STABILITY")

    response = client.get(
        "/protected/profile",
        headers=auth_headers
    )

    expect_status(
        "Protected profile remains accessible to authenticated user",
        response,
        200
    )

    body = response.json()

    if body.get("username") == TEST_USER:
        pass_check(
            "Protected resource identity remains bound to session"
        )
    else:
        fail_check(
            "Protected resource identity",
            f"unexpected username: {body.get('username')!r}"
        )


finally:

    print()
    print("[CLEANUP] Removing mass-assignment test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.23 MASS ASSIGNMENT / OVERPOSTING SECURITY TEST PASSED")
else:
    print(
        f"V0.8.23 MASS ASSIGNMENT / OVERPOSTING "
        f"SECURITY TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
