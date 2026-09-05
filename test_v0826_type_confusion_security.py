from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0826TypeUser"
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
            f"identity changed to {body.get('username')!r}"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.26 TYPE CONFUSION / TYPE COERCION SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated type-confusion test user")

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
    # 1. INTEGER USERNAME
    # ============================================================

    print()
    print("[1] INTEGER USERNAME")

    response = client.post(
        "/login",
        json={
            "username": 123,
            "password": PASSWORD
        }
    )

    expect_status_family(
        "Integer username",
        response,
        {401, 422}
    )


    # ============================================================
    # 2. BOOLEAN USERNAME
    # ============================================================

    print()
    print("[2] BOOLEAN USERNAME")

    response = client.post(
        "/login",
        json={
            "username": True,
            "password": PASSWORD
        }
    )

    expect_status_family(
        "Boolean username",
        response,
        {401, 422}
    )


    # ============================================================
    # 3. FLOAT USERNAME
    # ============================================================

    print()
    print("[3] FLOAT USERNAME")

    response = client.post(
        "/login",
        json={
            "username": 123.45,
            "password": PASSWORD
        }
    )

    expect_status_family(
        "Float username",
        response,
        {401, 422}
    )


    # ============================================================
    # 4. ARRAY USERNAME
    # ============================================================

    print()
    print("[4] ARRAY USERNAME")

    response = client.post(
        "/login",
        json={
            "username": [
                TEST_USER
            ],
            "password": PASSWORD
        }
    )

    expect_status_family(
        "Array username",
        response,
        {401, 422}
    )


    # ============================================================
    # 5. OBJECT USERNAME
    # ============================================================

    print()
    print("[5] OBJECT USERNAME")

    response = client.post(
        "/login",
        json={
            "username": {
                "value": TEST_USER
            },
            "password": PASSWORD
        }
    )

    expect_status_family(
        "Object username",
        response,
        {401, 422}
    )


    # ============================================================
    # 6. INTEGER PASSWORD
    # ============================================================

    print()
    print("[6] INTEGER PASSWORD")

    response = client.post(
        "/login",
        json={
            "username": TEST_USER,
            "password": 123456789
        }
    )

    expect_status_family(
        "Integer password",
        response,
        {401, 422}
    )


    # ============================================================
    # 7. BOOLEAN PASSWORD
    # ============================================================

    print()
    print("[7] BOOLEAN PASSWORD")

    response = client.post(
        "/login",
        json={
            "username": TEST_USER,
            "password": True
        }
    )

    expect_status_family(
        "Boolean password",
        response,
        {401, 422}
    )


    # ============================================================
    # 8. ARRAY PASSWORD
    # ============================================================

    print()
    print("[8] ARRAY PASSWORD")

    response = client.post(
        "/login",
        json={
            "username": TEST_USER,
            "password": [
                PASSWORD
            ]
        }
    )

    expect_status_family(
        "Array password",
        response,
        {401, 422}
    )


    # ============================================================
    # 9. INTEGER CHALLENGE USERNAME
    # ============================================================

    print()
    print("[9] CHALLENGE USERNAME TYPE")

    response = client.post(
        "/auth/challenge",
        json={
            "username": 123
        }
    )

    expect_status_family(
        "Integer challenge username",
        response,
        {401, 422}
    )


    # ============================================================
    # 10. VERIFY FIELD TYPE CONFUSION
    # ============================================================

    print()
    print("[10] VERIFY FIELD TYPES")

    verify_variants = [
        {
            "username": TEST_USER,
            "challenge": 123,
            "signature": "invalid"
        },
        {
            "username": TEST_USER,
            "challenge": "invalid",
            "signature": 123
        },
        {
            "username": 123,
            "challenge": "invalid",
            "signature": "invalid"
        },
        {
            "username": True,
            "challenge": False,
            "signature": []
        },
    ]

    for payload in verify_variants:

        response = client.post(
            "/auth/verify",
            json=payload
        )

        expect_status_family(
            f"Verify type variant {payload!r}",
            response,
            {401, 422}
        )


    # ============================================================
    # 11. PROFILE DISPLAY_NAME TYPE CONFUSION
    # ============================================================

    print()
    print("[11] PROFILE DISPLAY_NAME TYPES")

    profile_variants = [
        123,
        True,
        123.45,
        [TEST_USER],
        {
            "value": TEST_USER
        },
        None,
    ]

    for value in profile_variants:

        response = client.put(
            "/protected/profile/write",
            json={
                "display_name": value
            },
            headers=auth_headers
        )

        # Authorization should still stop the isolated user.
        # If schema validation runs first in another configuration,
        # 422 is also safe.
        expect_status_family(
            f"Profile display_name type {value!r}",
            response,
            {403, 422}
        )


    # ============================================================
    # 12. SECURITY-SENSITIVE TYPE CONFUSION
    # ============================================================

    print()
    print("[12] SECURITY-SENSITIVE TYPE CONFUSION")

    payloads = [
        {
            "username": True,
            "password": "wrong"
        },
        {
            "username": 1,
            "password": "wrong"
        },
        {
            "username": ["admin"],
            "password": "wrong"
        },
        {
            "username": {
                "username": "admin"
            },
            "password": "wrong"
        },
    ]

    for payload in payloads:

        response = client.post(
            "/login",
            json=payload
        )

        # None of these alternate representations may authenticate.
        expect_status_family(
            f"Security-sensitive login payload {payload!r}",
            response,
            {401, 422}
        )

        if response.status_code == 200:
            fail_check(
                "Type confusion authentication bypass",
                f"unexpected successful authentication for {payload!r}"
            )


    # ============================================================
    # 13. TYPE CONFUSION MUST NOT ALTER SESSION IDENTITY
    # ============================================================

    print()
    print("[13] SESSION IDENTITY STABILITY")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    check_identity(
        "Session identity after type-confusion attempts",
        response
    )


    # ============================================================
    # 14. TYPE CONFUSION MUST NOT ALTER AUTHORIZATION
    # ============================================================

    print()
    print("[14] AUTHORIZATION STABILITY")

    response = client.get(
        "/admin/users",
        headers=auth_headers
    )

    if response.status_code == 403:
        pass_check(
            "Admin access remains denied after type-confusion attempts"
        )
    else:
        fail_check(
            "Authorization after type-confusion attempts",
            f"expected HTTP 403, got HTTP {response.status_code}"
        )


    # ============================================================
    # 15. NORMAL FUNCTIONALITY AFTER TYPE CONFUSION
    # ============================================================

    print()
    print("[15] POST-ATTACK FUNCTIONALITY")

    response = client.get(
        "/protected/profile",
        headers=auth_headers
    )

    expect_status_family(
        "Protected profile after type-confusion tests",
        response,
        {200}
    )

    check_identity(
        "Protected profile identity",
        response
    )


finally:

    print()
    print("[CLEANUP] Removing type-confusion test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.26 TYPE CONFUSION / TYPE COERCION SECURITY TEST PASSED")
else:
    print(
        f"V0.8.26 TYPE CONFUSION / TYPE COERCION "
        f"SECURITY TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
