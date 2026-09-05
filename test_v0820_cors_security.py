from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0820CorsUser"
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


def expect_absent_header(label, response, header_name):
    value = response.headers.get(header_name)

    if value is None:
        pass_check(
            f"{label}: {header_name} absent"
        )
    else:
        fail_check(
            label,
            f"{header_name} unexpectedly present: {value!r}"
        )


def expect_not_reflected_origin(label, response, origin):
    value = response.headers.get("Access-Control-Allow-Origin")

    if value != origin:
        pass_check(
            f"{label}: origin not reflected"
        )
    else:
        fail_check(
            label,
            "Access-Control-Allow-Origin reflected attacker origin"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.20 CORS SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated CORS test user")

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
    # 1. PUBLIC ENDPOINT + ATTACKER ORIGIN
    # ============================================================

    print()
    print("[1] PUBLIC ENDPOINT / ATTACKER ORIGIN")

    response = client.get(
        "/health",
        headers={
            "Origin": "https://evil.example"
        }
    )

    expect_status(
        "GET /health from attacker origin",
        response,
        200
    )

    expect_absent_header(
        "Attacker origin on /health",
        response,
        "Access-Control-Allow-Origin"
    )

    expect_absent_header(
        "Attacker origin on /health",
        response,
        "Access-Control-Allow-Credentials"
    )


    # ============================================================
    # 2. PROTECTED ENDPOINT + ATTACKER ORIGIN
    # ============================================================

    print()
    print("[2] PROTECTED ENDPOINT / ATTACKER ORIGIN")

    response = client.get(
        "/session",
        headers={
            **auth_headers,
            "Origin": "https://evil.example"
        }
    )

    expect_status(
        "GET /session from attacker origin",
        response,
        200
    )

    expect_absent_header(
        "Attacker origin on protected response",
        response,
        "Access-Control-Allow-Origin"
    )

    expect_absent_header(
        "Attacker origin on protected response",
        response,
        "Access-Control-Allow-Credentials"
    )


    # ============================================================
    # 3. ORIGIN REFLECTION TEST
    # ============================================================

    print()
    print("[3] ORIGIN REFLECTION")

    malicious_origins = [
        "https://evil.example",
        "https://attacker.example",
        "null",
        "https://evil.example.attacker.com",
    ]

    for origin in malicious_origins:

        response = client.get(
            "/session",
            headers={
                **auth_headers,
                "Origin": origin
            }
        )

        expect_not_reflected_origin(
            f"Origin reflection test: {origin}",
            response,
            origin
        )


    # ============================================================
    # 4. CORS WILDCARD TEST
    # ============================================================

    print()
    print("[4] WILDCARD CORS")

    response = client.get(
        "/session",
        headers={
            **auth_headers,
            "Origin": "https://evil.example"
        }
    )

    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    if allow_origin != "*":
        pass_check(
            "Protected endpoint does not expose Access-Control-Allow-Origin: *"
        )
    else:
        fail_check(
            "Wildcard CORS",
            "protected endpoint returned Access-Control-Allow-Origin: *"
        )


    # ============================================================
    # 5. CREDENTIALS CORS TEST
    # ============================================================

    print()
    print("[5] CORS CREDENTIALS")

    response = client.get(
        "/session",
        headers={
            **auth_headers,
            "Origin": "https://evil.example"
        }
    )

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials"
    )

    if allow_credentials is None:
        pass_check(
            "Access-Control-Allow-Credentials is absent"
        )
    elif allow_credentials.lower() != "true":
        pass_check(
            "Access-Control-Allow-Credentials is not enabled"
        )
    else:
        fail_check(
            "CORS credentials",
            "Access-Control-Allow-Credentials: true exposed"
        )


    # ============================================================
    # 6. PREFLIGHT OPTIONS / ADMIN ENDPOINT
    # ============================================================

    print()
    print("[6] PREFLIGHT / ADMIN ENDPOINT")

    response = client.options(
        "/admin/users",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "Authorization"
        }
    )

    if response.status_code in (404, 405):
        pass_check(
            f"Cross-origin preflight to /admin/users rejected -> "
            f"HTTP {response.status_code}"
        )
    else:
        fail_check(
            "Admin CORS preflight",
            f"unexpected HTTP {response.status_code}"
        )

    expect_absent_header(
        "Admin preflight",
        response,
        "Access-Control-Allow-Origin"
    )

    expect_absent_header(
        "Admin preflight",
        response,
        "Access-Control-Allow-Credentials"
    )


    # ============================================================
    # 7. PREFLIGHT / PROFILE WRITE
    # ============================================================

    print()
    print("[7] PREFLIGHT / PROFILE WRITE")

    response = client.options(
        "/protected/profile/write",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": (
                "Authorization, Content-Type"
            )
        }
    )

    if response.status_code in (404, 405):
        pass_check(
            f"Cross-origin preflight to profile/write rejected -> "
            f"HTTP {response.status_code}"
        )
    else:
        fail_check(
            "Profile write CORS preflight",
            f"unexpected HTTP {response.status_code}"
        )

    expect_absent_header(
        "Profile write preflight",
        response,
        "Access-Control-Allow-Origin"
    )

    expect_absent_header(
        "Profile write preflight",
        response,
        "Access-Control-Allow-Methods"
    )


    # ============================================================
    # 8. CORS CANNOT BYPASS AUTHENTICATION
    # ============================================================

    print()
    print("[8] CORS / AUTHENTICATION BOUNDARY")

    response = client.get(
        "/session",
        headers={
            "Origin": "https://evil.example"
        }
    )

    expect_status(
        "Cross-origin request without Authorization",
        response,
        401
    )

    expect_absent_header(
        "Unauthenticated CORS response",
        response,
        "Access-Control-Allow-Origin"
    )


    # ============================================================
    # 9. CORS CANNOT BYPASS AUTHORIZATION
    # ============================================================

    print()
    print("[9] CORS / AUTHORIZATION BOUNDARY")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "Origin": "https://evil.example"
        }
    )

    expect_status(
        "Normal user + attacker origin -> admin endpoint",
        response,
        403
    )

    expect_absent_header(
        "Unauthorized admin response",
        response,
        "Access-Control-Allow-Origin"
    )


    # ============================================================
    # 10. ORIGIN CAN BE SPOOFED OUTSIDE BROWSER
    # ============================================================

    print()
    print("[10] ORIGIN IS NOT AUTHENTICATION")

    response = client.get(
        "/session",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": "https://trusted.example"
        }
    )

    expect_status(
        "Spoofed trusted-looking origin with valid token",
        response,
        200
    )

    body = response.json()

    if body.get("username") == TEST_USER:
        pass_check(
            "Application identity remains based on session token"
        )
    else:
        fail_check(
            "Origin versus identity",
            f"unexpected username: {body.get('username')!r}"
        )


    # ============================================================
    # 11. NON-BROWSER ORIGIN VALUE
    # ============================================================

    print()
    print("[11] NON-BROWSER ORIGIN VALUE")

    response = client.get(
        "/health",
        headers={
            "Origin": "null"
        }
    )

    expect_status(
        "GET /health with Origin: null",
        response,
        200
    )

    expect_absent_header(
        "Origin null response",
        response,
        "Access-Control-Allow-Origin"
    )


    # ============================================================
    # 12. NORMAL SAME-ORIGIN FUNCTIONALITY
    # ============================================================

    print()
    print("[12] NORMAL API FUNCTIONALITY")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    expect_status(
        "Normal session request without Origin",
        response,
        200
    )

    body = response.json()

    if body.get("authenticated") is True:
        pass_check(
            "Normal authenticated API response remains functional"
        )
    else:
        fail_check(
            "Normal API functionality",
            "authenticated response flag missing or false"
        )


finally:

    print()
    print("[CLEANUP] Removing CORS test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.20 CORS SECURITY TEST PASSED")
else:
    print(
        f"V0.8.20 CORS SECURITY TEST FAILED: "
        f"{failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
