from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0822HeaderUser"
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


def check_injected_header_absent(label, response, header_name):
    value = response.headers.get(header_name)

    if value is None:
        pass_check(
            f"{label}: {header_name} absent"
        )
    else:
        fail_check(
            label,
            f"unexpected injected header present: {header_name}: {value!r}"
        )


def check_no_crlf_in_response_headers(label, response):
    for name, value in response.headers.items():

        if "\r" in value or "\n" in value:
            fail_check(
                label,
                f"CR/LF found in response header {name!r}: {value!r}"
            )
            return

    pass_check(
        f"{label}: no CR/LF in response headers"
    )


try:

    print("=" * 70)
    print("DPAS V0.8.22 HTTP HEADER INJECTION / RESPONSE SPLITTING TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated header-injection test user")

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
    # 1. CRLF IN PROFILE DISPLAY NAME
    # ============================================================

    print()
    print("[1] CRLF IN USER-CONTROLLED VALUE")

    payloads = [
        "Normal\r\nX-Test-Injected: yes",
        "Normal\rX-Test-Injected: yes",
        "Normal\nX-Test-Injected: yes",
        "Normal\r\nSet-Cookie: attacker=1",
        "Normal\r\nLocation: https://evil.example",
    ]

    for payload in payloads:

        response = client.put(
            "/protected/profile/write",
            json={
                "display_name": payload
            },
            headers=auth_headers
        )

        # The isolated user has no profile.write permission,
        # so authorization may stop processing before the value
        # is used. It is still important that the server does not
        # emit an attacker-controlled response header.
        expect_status_family(
            f"Profile payload {payload!r}",
            response,
            {403, 422}
        )

        check_injected_header_absent(
            f"Profile payload {payload!r}",
            response,
            "X-Test-Injected"
        )

        check_injected_header_absent(
            f"Profile payload {payload!r}",
            response,
            "Set-Cookie"
        )

        check_injected_header_absent(
            f"Profile payload {payload!r}",
            response,
            "Location"
        )

        check_no_crlf_in_response_headers(
            f"Profile payload {payload!r}",
            response
        )


    # ============================================================
    # 2. CRLF IN LOGIN USERNAME
    # ============================================================

    print()
    print("[2] CRLF IN LOGIN USERNAME")

    login_payloads = [
        "V0822\r\nX-Test-Injected: yes",
        "V0822\rX-Test-Injected: yes",
        "V0822\nX-Test-Injected: yes",
        "V0822\r\nSet-Cookie: attacker=1",
    ]

    for username in login_payloads:

        response = client.post(
            "/login",
            json={
                "username": username,
                "password": PASSWORD
            }
        )

        expect_status_family(
            f"Login username payload {username!r}",
            response,
            {401, 422}
        )

        check_injected_header_absent(
            f"Login username payload {username!r}",
            response,
            "X-Test-Injected"
        )

        check_injected_header_absent(
            f"Login username payload {username!r}",
            response,
            "Set-Cookie"
        )

        check_no_crlf_in_response_headers(
            f"Login username payload {username!r}",
            response
        )


    # ============================================================
    # 3. URL-ENCODED CRLF SEQUENCES
    # ============================================================

    print()
    print("[3] ENCODED CRLF SEQUENCES")

    encoded_payloads = [
        "V0822%0d%0aX-Test-Injected:%20yes",
        "V0822%0aX-Test-Injected:%20yes",
        "V0822%0dX-Test-Injected:%20yes",
    ]

    for username in encoded_payloads:

        response = client.post(
            "/login",
            json={
                "username": username,
                "password": PASSWORD
            }
        )

        expect_status_family(
            f"Encoded CRLF username {username!r}",
            response,
            {401, 422}
        )

        check_injected_header_absent(
            f"Encoded CRLF username {username!r}",
            response,
            "X-Test-Injected"
        )

        check_no_crlf_in_response_headers(
            f"Encoded CRLF username {username!r}",
            response
        )


    # ============================================================
    # 4. CRLF IN AUTH CHALLENGE USERNAME
    # ============================================================

    print()
    print("[4] CRLF IN AUTH CHALLENGE")

    challenge_payloads = [
        "V0822\r\nX-Test-Injected: yes",
        "V0822\r\nSet-Cookie: attacker=1",
        "V0822\nLocation: https://evil.example",
    ]

    for username in challenge_payloads:

        response = client.post(
            "/auth/challenge",
            json={
                "username": username
            }
        )

        expect_status_family(
            f"Challenge username {username!r}",
            response,
            {401, 422}
        )

        check_injected_header_absent(
            f"Challenge username {username!r}",
            response,
            "X-Test-Injected"
        )

        check_injected_header_absent(
            f"Challenge username {username!r}",
            response,
            "Set-Cookie"
        )

        check_injected_header_absent(
            f"Challenge username {username!r}",
            response,
            "Location"
        )

        check_no_crlf_in_response_headers(
            f"Challenge username {username!r}",
            response
        )


    # ============================================================
    # 5. CRLF IN AUTH VERIFY FIELDS
    # ============================================================

    print()
    print("[5] CRLF IN AUTH VERIFY FIELDS")

    verify_payloads = [
        {
            "username": "V0822\r\nX-Test-Injected: yes",
            "challenge": "test",
            "signature": "test",
        },
        {
            "username": "V0822",
            "challenge": "test\r\nX-Test-Injected: yes",
            "signature": "test",
        },
        {
            "username": "V0822",
            "challenge": "test",
            "signature": "test\r\nX-Test-Injected: yes",
        },
    ]

    for payload in verify_payloads:

        response = client.post(
            "/auth/verify",
            json=payload
        )

        expect_status_family(
            f"Verify payload {payload!r}",
            response,
            {401, 422}
        )

        check_injected_header_absent(
            f"Verify payload {payload!r}",
            response,
            "X-Test-Injected"
        )

        check_injected_header_absent(
            f"Verify payload {payload!r}",
            response,
            "Set-Cookie"
        )

        check_injected_header_absent(
            f"Verify payload {payload!r}",
            response,
            "Location"
        )

        check_no_crlf_in_response_headers(
            f"Verify payload {payload!r}",
            response
        )


    # ============================================================
    # 6. RESPONSE HEADER NAME INJECTION ATTEMPT
    # ============================================================

    print()
    print("[6] RESPONSE HEADER NAME INJECTION")

    response = client.get(
        "/session",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Test\r\nInjected": "yes"
        }
    )

    expect_status_family(
        "Malicious request header name",
        response,
        {200, 400}
    )

    check_injected_header_absent(
        "Malicious request header name",
        response,
        "Injected"
    )

    check_no_crlf_in_response_headers(
        "Malicious request header name",
        response
    )


    # ============================================================
    # 7. RESPONSE SPLITTING MARKERS
    # ============================================================

    print()
    print("[7] RESPONSE SPLITTING MARKERS")

    splitting_payloads = [
        "\r\n\r\n",
        "\r\nHTTP/1.1 200 OK",
        "\n\n",
        "\r\r",
    ]

    for payload in splitting_payloads:

        response = client.post(
            "/login",
            json={
                "username": "V0822" + payload,
                "password": PASSWORD
            }
        )

        expect_status_family(
            f"Response-splitting payload {payload!r}",
            response,
            {401, 422}
        )

        check_no_crlf_in_response_headers(
            f"Response-splitting payload {payload!r}",
            response
        )

        check_injected_header_absent(
            f"Response-splitting payload {payload!r}",
            response,
            "X-Test-Injected"
        )


    # ============================================================
    # 8. NORMAL RESPONSE HEADERS REMAIN VALID
    # ============================================================

    print()
    print("[8] NORMAL SECURITY HEADERS")

    response = client.get(
        "/session",
        headers=auth_headers
    )

    expect_status_family(
        "Normal authenticated /session",
        response,
        {200}
    )

    expected_headers = {
        "Cache-Control": "no-store",
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

    check_no_crlf_in_response_headers(
        "Normal authenticated response"
        ,
        response
    )


finally:

    print()
    print("[CLEANUP] Removing header-injection test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.22 HTTP HEADER INJECTION / RESPONSE SPLITTING TEST PASSED")
else:
    print(
        f"V0.8.22 HTTP HEADER INJECTION / RESPONSE SPLITTING "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
