from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user
from app.session_manager import create_user_session, logout


TEST_USER = "V0819MethodUser"
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

    print("=" * 70)
    print("DPAS V0.8.19 HTTP METHOD OVERRIDE / VERB TAMPERING SECURITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated method-tampering test user")

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
    # 1. X-HTTP-METHOD-OVERRIDE MUST NOT CHANGE GET SEMANTICS
    # ============================================================

    print()
    print("[1] X-HTTP-METHOD-OVERRIDE")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "DELETE"
        }
    )

    expect_status(
        "GET /admin/users + X-HTTP-Method-Override DELETE",
        response,
        403
    )


    # ============================================================
    # 2. X-METHOD-OVERRIDE MUST NOT CHANGE GET SEMANTICS
    # ============================================================

    print()
    print("[2] X-METHOD-OVERRIDE")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "X-Method-Override": "DELETE"
        }
    )

    expect_status(
        "GET /admin/users + X-Method-Override DELETE",
        response,
        403
    )


    # ============================================================
    # 3. X-HTTP-METHOD MUST NOT CHANGE ROUTING
    # ============================================================

    print()
    print("[3] X-HTTP-METHOD")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method": "DELETE"
        }
    )

    expect_status(
        "GET /admin/users + X-HTTP-Method DELETE",
        response,
        403
    )


    # ============================================================
    # 4. POST + OVERRIDE DELETE CANNOT BYPASS ADMIN AUTH
    # ============================================================

    print()
    print("[4] POST + DELETE OVERRIDE")

    response = client.post(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "DELETE"
        }
    )

    expect_status(
        "POST /admin/users + DELETE override",
        response,
        405
    )


    # ============================================================
    # 5. POST + OVERRIDE GET CANNOT BECOME ADMIN GET
    # ============================================================

    print()
    print("[5] POST + GET OVERRIDE")

    response = client.post(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "GET"
        }
    )

    expect_status(
        "POST /admin/users + GET override",
        response,
        405
    )


    # ============================================================
    # 6. GET + OVERRIDE POST CANNOT BECOME WRITE OPERATION
    # ============================================================

    print()
    print("[6] GET + POST OVERRIDE")

    response = client.get(
        "/protected/profile/write",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "POST"
        }
    )

    expect_status(
        "GET profile/write + POST override",
        response,
        405
    )


    # ============================================================
    # 7. GET + OVERRIDE PUT CANNOT REACH WRITE ROUTE
    # ============================================================

    print()
    print("[7] GET + PUT OVERRIDE")

    response = client.get(
        "/protected/profile/write",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "PUT"
        }
    )

    expect_status(
        "GET profile/write + PUT override",
        response,
        405
    )


    # ============================================================
    # 8. PATCH CANNOT BECOME PUT THROUGH OVERRIDE
    # ============================================================

    print()
    print("[8] PATCH + PUT OVERRIDE")

    response = client.patch(
        "/protected/profile/write",
        json={
            "display_name": "V0819"
        },
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "PUT"
        }
    )

    expect_status(
        "PATCH profile/write + PUT override",
        response,
        405
    )


    # ============================================================
    # 9. DELETE CANNOT BECOME GET THROUGH OVERRIDE
    # ============================================================

    print()
    print("[9] DELETE + GET OVERRIDE")

    response = client.delete(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "GET"
        }
    )

    expect_status(
        "DELETE /admin/users + GET override",
        response,
        405
    )


    # ============================================================
    # 10. OVERRIDE HEADER CANNOT CHANGE AUTHORIZATION IDENTITY
    # ============================================================

    print()
    print("[10] METHOD OVERRIDE / IDENTITY BOUNDARY")

    response = client.get(
        "/session",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "POST"
        }
    )

    expect_status(
        "GET /session + POST override",
        response,
        200
    )

    body = response.json()

    if body.get("username") == TEST_USER:
        pass_check("Method override did not change session identity")
    else:
        fail_check(
            "Method override session identity",
            f"expected username {TEST_USER}, got {body.get('username')}"
        )


    # ============================================================
    # 11. MULTIPLE OVERRIDE HEADERS MUST NOT ESCALATE PRIVILEGE
    # ============================================================

    print()
    print("[11] MULTIPLE OVERRIDE HEADERS")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "GET",
            "X-Method-Override": "DELETE",
            "X-HTTP-Method": "POST"
        }
    )

    expect_status(
        "GET /admin/users with conflicting override headers",
        response,
        403
    )


    # ============================================================
    # 12. CASE VARIATIONS MUST NOT ALTER ROUTING
    # ============================================================

    print()
    print("[12] OVERRIDE CASE VARIATIONS")

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "delete"
        }
    )

    expect_status(
        "GET /admin/users + lowercase delete override",
        response,
        403
    )

    response = client.get(
        "/admin/users",
        headers={
            **auth_headers,
            "X-HTTP-Method-Override": "DeLeTe"
        }
    )

    expect_status(
        "GET /admin/users + mixed-case delete override",
        response,
        403
    )


    # ============================================================
    # 13. UNKNOWN VERB MUST NOT FALL BACK TO AUTHORIZED ROUTE
    # ============================================================

    print()
    print("[13] UNKNOWN VERB")

    response = client.request(
        "BREW",
        "/admin/users",
        headers=auth_headers
    )

    expect_status(
        "Unknown HTTP verb on admin endpoint",
        response,
        405
    )


    # ============================================================
    # 14. TRACE MUST NOT EXPOSE PROTECTED RESOURCE
    # ============================================================

    print()
    print("[14] TRACE")

    response = client.request(
        "TRACE",
        "/admin/users",
        headers=auth_headers
    )

    if response.status_code in (404, 405):
        pass_check(
            f"TRACE /admin/users rejected -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            "TRACE /admin/users",
            f"unexpected HTTP {response.status_code}"
        )


    # ============================================================
    # 15. CONNECT MUST NOT EXPOSE PROTECTED RESOURCE
    # ============================================================

    print()
    print("[15] CONNECT")

    response = client.request(
        "CONNECT",
        "/admin/users",
        headers=auth_headers
    )

    if response.status_code in (404, 405):
        pass_check(
            f"CONNECT /admin/users rejected -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            "CONNECT /admin/users",
            f"unexpected HTTP {response.status_code}"
        )


    # ============================================================
    # 16. NORMAL AUTHORIZATION MUST STILL WORK
    # ============================================================

    print()
    print("[16] FINAL AUTHORIZATION CONTROL")

    response = client.get(
        "/admin/users",
        headers=auth_headers
    )

    expect_status(
        "Normal user -> admin endpoint",
        response,
        403
    )

    response = client.get(
        "/session",
        headers=auth_headers
    )

    expect_status(
        "Normal user -> session endpoint",
        response,
        200
    )


finally:

    print()
    print("[CLEANUP] Removing method-tampering test user and session")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.19 HTTP METHOD OVERRIDE / VERB TAMPERING SECURITY TEST PASSED")
else:
    print(
        f"V0.8.19 HTTP METHOD OVERRIDE / VERB TAMPERING "
        f"SECURITY TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
