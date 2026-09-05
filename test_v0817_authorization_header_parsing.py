from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0817HeaderUser"
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
            f"expected HTTP {expected}, "
            f"got HTTP {response.status_code}"
        )


try:

    # ============================================================
    # SETUP
    # ============================================================

    print("=" * 70)
    print("DPAS V0.8.17 AUTHORIZATION HEADER / TOKEN PARSING TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated header parsing test user")

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

    valid_headers = {
        "Authorization": f"Bearer {token}"
    }


    # ============================================================
    # 1. VALID BEARER HEADER
    # ============================================================

    print()
    print("[1] VALID BEARER HEADER")

    response = client.get(
        "/session",
        headers=valid_headers
    )

    expect_status(
        "Valid Bearer token",
        response,
        200
    )

    if response.status_code == 200:

        body = response.json()

        if body.get("username") == TEST_USER:
            pass_check(
                "Valid Bearer token preserved session identity"
            )
        else:
            fail_check(
                "Valid Bearer session identity",
                "unexpected username"
            )


    # ============================================================
    # 2. MISSING AUTHORIZATION
    # ============================================================

    print()
    print("[2] MISSING AUTHORIZATION HEADER")

    response = client.get("/session")

    expect_status(
        "Missing Authorization header",
        response,
        401
    )


    # ============================================================
    # 3. EMPTY AUTHORIZATION VALUE
    # ============================================================

    print()
    print("[3] EMPTY AUTHORIZATION VALUE")

    response = client.get(
        "/session",
        headers={
            "Authorization": ""
        }
    )

    expect_status(
        "Empty Authorization header",
        response,
        401
    )


    # ============================================================
    # 4. BEARER WITHOUT TOKEN
    # ============================================================

    print()
    print("[4] BEARER WITHOUT TOKEN")

    for value in (
        "Bearer",
        "Bearer ",
        "Bearer    ",
    ):

        response = client.get(
            "/session",
            headers={
                "Authorization": value
            }
        )

        expect_status(
            f"Authorization: {value!r}",
            response,
            401
        )


    # ============================================================
    # 5. WRONG AUTHENTICATION SCHEME
    # ============================================================

    print()
    print("[5] WRONG AUTHENTICATION SCHEME")

    wrong_schemes = [
        "Basic " + token,
        "Token " + token,
        "Digest " + token,
        "Basic",
        "Token",
        "JWT " + token,
    ]

    for value in wrong_schemes:

        response = client.get(
            "/session",
            headers={
                "Authorization": value
            }
        )

        expect_status(
            f"Wrong scheme: {value.split(' ')[0]}",
            response,
            401
        )


    # ============================================================
    # 6. WRONG CASE FOR BEARER
    # ============================================================

    print()
    print("[6] BEARER CASE SENSITIVITY")

    case_variants = [
        "bearer " + token,
        "BEARER " + token,
        "Bearer".lower() + " " + token,
        "bEaReR " + token,
    ]

    for value in case_variants:

        response = client.get(
            "/session",
            headers={
                "Authorization": value
            }
        )

        expect_status(
            f"Non-canonical Bearer casing",
            response,
            401
        )


    # ============================================================
    # 7. EXTRA PREFIX / SUFFIX DATA
    # ============================================================

    print()
    print("[7] EXTRA HEADER DATA")

    malformed_values = [
        "BearerX " + token,
        "Bearer_" + token,
        "Bearer  " + token,
        "Bearer\t" + token,
        "Bearer " + token + " extra",
        "Bearer " + token + " ",
        "Bearer extra " + token,
    ]

    for value in malformed_values:

        response = client.get(
            "/session",
            headers={
                "Authorization": value
            }
        )

        # A header with a canonical token followed by one trailing
        # ASCII space is implementation-dependent in HTTP clients.
        # The important property is that malicious extra content
        # cannot authenticate as the test user.
        if value == "Bearer " + token + " ":
            if response.status_code == 200:
                body = response.json()

                if body.get("username") == TEST_USER:
                    pass_check(
                        "Single trailing space did not alter identity"
                    )
                else:
                    fail_check(
                        "Trailing-space identity",
                        "unexpected username"
                    )
            elif response.status_code == 401:
                pass_check(
                    "Single trailing space was rejected"
                )
            else:
                fail_check(
                    "Single trailing space",
                    f"unexpected HTTP {response.status_code}"
                )
        else:
            expect_status(
                f"Malformed Authorization value",
                response,
                401
            )


    # ============================================================
    # 8. MULTIPLE TOKEN VALUES
    # ============================================================

    print()
    print("[8] MULTIPLE TOKEN VALUES")

    multiple_token_values = [
        f"Bearer {token} {token}",
        f"Bearer {token},{token}",
        f"Bearer {token};{token}",
        f"Bearer {token}\t{token}",
    ]

    for value in multiple_token_values:

        response = client.get(
            "/session",
            headers={
                "Authorization": value
            }
        )

        expect_status(
            "Multiple token values in Authorization",
            response,
            401
        )


    # ============================================================
    # 9. EMPTY / WHITESPACE TOKEN AFTER BEARER
    # ============================================================

    print()
    print("[9] EMPTY / WHITESPACE TOKEN")

    whitespace_values = [
        "Bearer\t",
        "Bearer\t\t",
        "Bearer \t",
        "Bearer \t\t",
    ]

    for value in whitespace_values:

        response = client.get(
            "/session",
            headers={
                "Authorization": value
            }
        )

        expect_status(
            "Whitespace-only token",
            response,
            401
        )


    # ============================================================
    # 10. TAMPERED TOKEN
    # ============================================================

    print()
    print("[10] TAMPERED TOKEN")

    tampered_tokens = [
        token + "A",
        "A" + token,
        token[:-1],
        token.replace(token[0], "X", 1),
    ]

    for tampered in tampered_tokens:

        response = client.get(
            "/session",
            headers={
                "Authorization": f"Bearer {tampered}"
            }
        )

        expect_status(
            "Tampered session token",
            response,
            401
        )


    # ============================================================
    # 11. TOKEN AS HEADER VALUE WITHOUT SCHEME
    # ============================================================

    print()
    print("[11] RAW TOKEN WITHOUT SCHEME")

    response = client.get(
        "/session",
        headers={
            "Authorization": token
        }
    )

    expect_status(
        "Raw token without Bearer scheme",
        response,
        401
    )


    # ============================================================
    # 12. HEADER INJECTION-LIKE CONTENT
    # ============================================================

    print()
    print("[12] HEADER INJECTION-LIKE CONTENT")

    injection_values = [
        f"Bearer {token}\r\nX-Test: injected",
        f"Bearer {token}\nX-Test: injected",
        f"Bearer {token}\r\nAuthorization: Bearer {token}",
    ]

    for value in injection_values:

        try:
            response = client.get(
                "/session",
                headers={
                    "Authorization": value
                }
            )

            if response.status_code != 200:
                pass_check(
                    "Header injection-like value rejected "
                    f"(HTTP {response.status_code})"
                )
            else:
                body = response.json()

                if body.get("username") == TEST_USER:
                    fail_check(
                        "Header injection-like value",
                        "request authenticated unexpectedly"
                    )
                else:
                    pass_check(
                        "Header injection-like value did not "
                        "produce authenticated test user"
                    )

        except Exception:
            pass_check(
                "Header injection-like value rejected by HTTP layer"
            )


    # ============================================================
    # 13. AUTHORIZATION BOUNDARY STILL HOLDS
    # ============================================================

    print()
    print("[13] FINAL AUTHORIZATION BOUNDARY")

    response = client.get(
        "/protected/profile",
        headers=valid_headers
    )

    expect_status(
        "Valid token -> protected profile",
        response,
        200
    )

    response = client.get(
        "/admin/users",
        headers=valid_headers
    )

    # Test user has no admin role.
    expect_status(
        "Normal token -> admin endpoint",
        response,
        403
    )


finally:

    print()
    print("[CLEANUP] Removing header parsing test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.17 AUTHORIZATION HEADER / TOKEN PARSING TEST PASSED")
else:
    print(
        f"V0.8.17 AUTHORIZATION HEADER / TOKEN PARSING "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
