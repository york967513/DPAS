from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0825BodyUser"
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


def check_response_stable(label, response):
    if response.status_code in (400, 413, 422):
        pass_check(
            f"{label}: controlled rejection"
        )
    elif response.status_code in (401, 403):
        pass_check(
            f"{label}: authorization rejected request safely"
        )
    else:
        fail_check(
            label,
            f"unexpected response HTTP {response.status_code}"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.25 REQUEST BODY SIZE / RESOURCE EXHAUSTION TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated request-size test user")

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
    # 1. NORMAL SMALL REQUEST
    # ============================================================

    print()
    print("[1] NORMAL REQUEST")

    response = client.post(
        "/login",
        json={
            "username": "V0825Unknown",
            "password": "wrong"
        }
    )

    expect_status_family(
        "Normal small JSON request",
        response,
        {401}
    )


    # ============================================================
    # 2. 64 KB STRING
    # ============================================================

    print()
    print("[2] 64 KB REQUEST")

    payload_64k = {
        "username": "V0825_" + ("A" * (64 * 1024)),
        "password": "wrong"
    }

    response = client.post(
        "/login",
        json=payload_64k
    )

    check_response_stable(
        "Approximately 64 KB login request",
        response
    )


    # ============================================================
    # 3. 256 KB STRING
    # ============================================================

    print()
    print("[3] 256 KB REQUEST")

    payload_256k = {
        "username": "V0825_" + ("A" * (256 * 1024)),
        "password": "wrong"
    }

    response = client.post(
        "/login",
        json=payload_256k
    )

    check_response_stable(
        "Approximately 256 KB login request",
        response
    )


    # ============================================================
    # 4. 1 MB STRING
    # ============================================================

    print()
    print("[4] 1 MB REQUEST")

    payload_1mb = {
        "username": "V0825_" + ("A" * (1024 * 1024)),
        "password": "wrong"
    }

    response = client.post(
        "/login",
        json=payload_1mb
    )

    check_response_stable(
        "Approximately 1 MB login request",
        response
    )


    # ============================================================
    # 5. LARGE PROFILE BODY
    # ============================================================

    print()
    print("[5] LARGE PROTECTED BODY")

    payload_profile = {
        "display_name": "V0825_" + ("B" * (1024 * 1024))
    }

    response = client.put(
        "/protected/profile/write",
        json=payload_profile,
        headers=auth_headers
    )

    # Authorization is expected to stop this isolated user before
    # the application performs the profile operation.
    expect_status_family(
        "Approximately 1 MB profile request",
        response,
        {403, 413, 422}
    )


    # ============================================================
    # 6. LARGE AUTH CHALLENGE BODY
    # ============================================================

    print()
    print("[6] LARGE CHALLENGE BODY")

    payload_challenge = {
        "username": "V0825_" + ("C" * (1024 * 1024))
    }

    response = client.post(
        "/auth/challenge",
        json=payload_challenge
    )

    check_response_stable(
        "Approximately 1 MB challenge request",
        response
    )


    # ============================================================
    # 7. LARGE VERIFY BODY
    # ============================================================

    print()
    print("[7] LARGE VERIFY BODY")

    payload_verify = {
        "username": "V0825_" + ("D" * (512 * 1024)),
        "challenge": "E" * (256 * 1024),
        "signature": "F" * (256 * 1024)
    }

    response = client.post(
        "/auth/verify",
        json=payload_verify
    )

    check_response_stable(
        "Approximately 1 MB verify request",
        response
    )


    # ============================================================
    # 8. MANY JSON FIELDS
    # ============================================================

    print()
    print("[8] MANY JSON FIELDS")

    many_fields = {
        f"field_{index}": "X" * 2048
        for index in range(512)
    }

    many_fields["username"] = "V0825Unknown"
    many_fields["password"] = "wrong"

    response = client.post(
        "/login",
        json=many_fields
    )

    check_response_stable(
        "Large JSON object with many extra fields",
        response
    )


    # ============================================================
    # 9. LARGE NESTED JSON STRUCTURE
    # ============================================================

    print()
    print("[9] LARGE NESTED JSON")

    nested = {
        "level": {
            "level": {
                "level": {
                    "value": "X" * (512 * 1024)
                }
            }
        }
    }

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "NestedTest",
            "metadata": nested
        },
        headers=auth_headers
    )

    expect_status_family(
        "Large nested JSON profile request",
        response,
        {403, 413, 422}
    )


    # ============================================================
    # 10. CONTENT-LENGTH MANIPULATION
    # ============================================================

    print()
    print("[10] CONTENT-LENGTH MANIPULATION")

    response = client.post(
        "/login",
        content='{"username":"V0825Unknown","password":"wrong"}',
        headers={
            "Content-Type": "application/json",
            "Content-Length": "999999999"
        }
    )

    # The HTTP client/server stack may normalize or reject an
    # inconsistent Content-Length. It must not produce successful
    # authentication.
    expect_status_family(
        "Forged Content-Length on small request",
        response,
        {400, 401, 422}
    )


    # ============================================================
    # 11. LARGE QUERY INPUT / AUTHORIZATION
    # ============================================================

    print()
    print("[11] LARGE QUERY INPUT / AUTHORIZATION")

    # Keep this deliberately below the HTTP client's URL-component
    # limit. The earlier 256 KB value never reached the server because
    # httpx2 rejected the URL locally.
    large_query = "X" * (32 * 1024)

    response = client.get(
        "/admin/users",
        params={
            "role": "admin",
            "permission": "users.delete",
            "padding": large_query
        },
        headers=auth_headers
    )

    expect_status_family(
        "32 KB query input against admin endpoint",
        response,
        {403, 414, 422}
    )


    # ============================================================
    # 12. APPLICATION MUST REMAIN RESPONSIVE
    # ============================================================

    print()
    print("[12] POST-LOAD APPLICATION HEALTH")

    response = client.get(
        "/health"
    )

    expect_status_family(
        "Health after large-request tests",
        response,
        {200}
    )

    body = response.json()

    if body.get("status") == "ok":
        pass_check(
            "Application remains responsive after large requests"
        )
    else:
        fail_check(
            "Application recovery",
            f"unexpected health response: {body!r}"
        )


    # ============================================================
    # 13. AUTHENTICATED SESSION REMAINS VALID
    # ============================================================

    print()
    print("[13] SESSION STABILITY")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    expect_status_family(
        "Session after large-request tests",
        response,
        {200}
    )

    if response.status_code == 200:

        body = response.json()

        if body.get("username") == TEST_USER:
            pass_check(
                "Session identity remains unchanged"
            )
        else:
            fail_check(
                "Session identity",
                f"unexpected username: {body.get('username')!r}"
            )


finally:

    print()
    print("[CLEANUP] Removing request-size test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.25 REQUEST BODY SIZE / RESOURCE EXHAUSTION TEST PASSED")
else:
    print(
        f"V0.8.25 REQUEST BODY SIZE / RESOURCE EXHAUSTION "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
