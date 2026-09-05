from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0818ContentUser"
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


try:

    # ============================================================
    # SETUP
    # ============================================================

    print("=" * 70)
    print("DPAS V0.8.18 HTTP CONTENT-TYPE / MEDIA-TYPE SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated content-type test user")

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
    # 1. NORMAL JSON LOGIN REQUEST
    # ============================================================

    print()
    print("[1] NORMAL JSON REQUEST")

    response = client.post(
        "/login",
        json={
            "username": "V0818Unknown",
            "password": PASSWORD,
        }
    )

    expect_status(
        "POST /login with application/json",
        response,
        401
    )


    # ============================================================
    # 2. EXPLICIT APPLICATION/JSON CONTENT TYPE
    # ============================================================

    print()
    print("[2] EXPLICIT APPLICATION/JSON")

    response = client.post(
        "/login",
        content='{"username":"V0818Unknown","password":"wrong"}',
        headers={
            "Content-Type": "application/json"
        }
    )

    expect_status(
        "POST /login with explicit application/json",
        response,
        401
    )


    # ============================================================
    # 3. TEXT/PLAIN MUST NOT BECOME VALID JSON
    # ============================================================

    print()
    print("[3] TEXT/PLAIN BODY")

    response = client.post(
        "/login",
        content='{"username":"V0818Unknown","password":"wrong"}',
        headers={
            "Content-Type": "text/plain"
        }
    )

    expect_status(
        "POST /login with text/plain containing JSON text",
        response,
        422
    )


    # ============================================================
    # 4. APPLICATION/XML
    # ============================================================

    print()
    print("[4] APPLICATION/XML")

    response = client.post(
        "/login",
        content=(
            "<login>"
            "<username>V0818Unknown</username>"
            "<password>wrong</password>"
            "</login>"
        ),
        headers={
            "Content-Type": "application/xml"
        }
    )

    expect_status(
        "POST /login with application/xml",
        response,
        422
    )


    # ============================================================
    # 5. FORM-URLENCODED MUST NOT AUTHENTICATE
    # ============================================================

    print()
    print("[5] FORM-URLENCODED BODY")

    response = client.post(
        "/login",
        content=(
            "username=V0818Unknown&"
            "password=wrong"
        ),
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )

    expect_status(
        "POST /login with form-urlencoded",
        response,
        422
    )


    # ============================================================
    # 6. MULTIPART FORM MUST NOT AUTHENTICATE
    # ============================================================

    print()
    print("[6] MULTIPART FORM")

    response = client.post(
        "/login",
        files={
            "username": (None, "V0818Unknown"),
            "password": (None, "wrong"),
        }
    )

    expect_status(
        "POST /login with multipart/form-data",
        response,
        422
    )


    # ============================================================
    # 7. MISSING CONTENT TYPE WITH JSON TEXT
    # ============================================================

    print()
    print("[7] MISSING CONTENT-TYPE")

    response = client.post(
        "/login",
        content='{"username":"V0818Unknown","password":"wrong"}'
    )

    # FastAPI may parse a body without an explicit Content-Type,
    # so the security requirement is not to authenticate a request
    # with invalid credentials.
    if response.status_code in (401, 422):
        pass_check(
            "JSON body without explicit Content-Type did not authenticate"
            f" (HTTP {response.status_code})"
        )
    else:
        fail_check(
            "JSON body without Content-Type",
            f"unexpected HTTP {response.status_code}"
        )


    # ============================================================
    # 8. APPLICATION/JSON WITH CHARSET
    # ============================================================

    print()
    print("[8] APPLICATION/JSON WITH CHARSET")

    response = client.post(
        "/login",
        content='{"username":"V0818Unknown","password":"wrong"}',
        headers={
            "Content-Type": "application/json; charset=utf-8"
        }
    )

    expect_status(
        "POST /login with application/json; charset=utf-8",
        response,
        401
    )


    # ============================================================
    # 9. UNSUPPORTED MEDIA TYPE / BODY VALIDATION
    # ============================================================

    print()
    print("[9] UNSUPPORTED MEDIA TYPE / BODY VALIDATION")

    response = client.post(
        "/auth/verify",
        content='{"username":"V0818Unknown","challenge":"x","signature":"y"}',
        headers={
            "Content-Type": "text/plain"
        }
    )

    expect_status(
        "POST /auth/verify with text/plain containing JSON",
        response,
        422
    )


    # ============================================================
    # 10. XML BODY
    # ============================================================

    print()
    print("[10] XML BODY")

    response = client.post(
        "/auth/verify",
        content=(
            "<verify>"
            "<username>V0818Unknown</username>"
            "<challenge>x</challenge>"
            "<signature>y</signature>"
            "</verify>"
        ),
        headers={
            "Content-Type": "application/xml"
        }
    )

    expect_status(
        "POST /auth/verify with application/xml",
        response,
        422
    )


    # ============================================================
    # 11. FORM BODY
    # ============================================================

    print()
    print("[11] FORM BODY")

    response = client.post(
        "/auth/verify",
        content="username=V0818Unknown&challenge=x&signature=y",
        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )

    expect_status(
        "POST /auth/verify with form-urlencoded",
        response,
        422
    )


    # ============================================================
    # 12. SECURITY-LOOKING JSON UNDER WRONG MEDIA TYPE
    # ============================================================

    print()
    print("[12] SECURITY-LOOKING JSON / WRONG MEDIA TYPE")

    response = client.post(
        "/auth/verify",
        content=(
            '{"username":"V0818Unknown",'
            '"challenge":"x",'
            '"signature":"y",'
            '"role":"admin",'
            '"permission":"users.delete"}'
        ),
        headers={
            "Content-Type": "text/plain"
        }
    )

    expect_status(
        "Security-looking JSON under text/plain",
        response,
        422
    )


    # ============================================================
    # 13. VALID JSON MUST STILL WORK FOR AUTHORIZED REQUEST
    # ============================================================

    print()
    print("[13] VALID JSON / AUTHORIZED REQUEST")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "V0818Valid"
        },
        headers=auth_headers
    )

    expect_status(
        "Valid application/json profile write",
        response,
        403
    )

    # The isolated user has no profile.write permission.
    # This confirms the request reached authorization rather than
    # being accepted solely because of the media type.


    # ============================================================
    # 14. HEALTH ENDPOINT DOES NOT REQUIRE BODY
    # ============================================================

    print()
    print("[14] BODYLESS ENDPOINT")

    response = client.get(
        "/health",
        headers={
            "Content-Type": "application/xml"
        }
    )

    expect_status(
        "GET /health with unrelated Content-Type",
        response,
        200
    )


    # ============================================================
    # 15. CONTENT-TYPE CANNOT BYPASS AUTHORIZATION
    # ============================================================

    print()
    print("[15] FINAL AUTHORIZATION / MEDIA-TYPE BOUNDARY")

    response = client.get(
        "/admin/users",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
    )

    expect_status(
        "Normal session -> admin endpoint with JSON Content-Type",
        response,
        403
    )

    response = client.get(
        "/admin/users",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "text/plain"
        }
    )

    expect_status(
        "Normal session -> admin endpoint with text/plain",
        response,
        403
    )


finally:

    print()
    print("[CLEANUP] Removing content-type test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.18 HTTP CONTENT-TYPE / MEDIA-TYPE SECURITY TEST PASSED")
else:
    print(
        f"V0.8.18 HTTP CONTENT-TYPE / MEDIA-TYPE SECURITY "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
