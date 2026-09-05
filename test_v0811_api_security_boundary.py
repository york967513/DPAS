import os
import sys
import time

from fastapi.testclient import TestClient

from app.api import app
from app.database import (
    get_connection,
    create_user,
    delete_user,
)
from app.auth import register_user
from app.session_manager import (
    create_user_session,
    logout,
)


NORMAL_USER = "V0811Normal"
ADMIN_USER = "V0811Admin"

TEST_PASSWORD = os.getenv(
    "DPAS_TEST_PASSWORD",
    "DPAS_Test_Password_2026!"
)


def cleanup():
    for username in (NORMAL_USER, ADMIN_USER):
        try:
            delete_user(username)
        except Exception:
            pass

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM audit_log
        WHERE username IN (?, ?)
        """,
        (NORMAL_USER, ADMIN_USER)
    )

    connection.commit()
    connection.close()


def create_registered_user(username):
    try:
        register_user(
            username,
            TEST_PASSWORD
        )
        return True
    except Exception:
        return False


print("=" * 70)
print("DPAS V0.8.11 API SECURITY BOUNDARY TEST")
print("=" * 70)

cleanup()

failures = 0
normal_token = None
admin_token = None

client = TestClient(app)

try:

    # ============================================================
    # SETUP
    # ============================================================

    print()
    print("[SETUP] Creating isolated API test users")

    if not create_registered_user(NORMAL_USER):
        print("[FAIL] Could not create normal test user")
        failures += 1

    if not create_registered_user(ADMIN_USER):
        print("[FAIL] Could not create admin test user")
        failures += 1

    # Promote only the dedicated test admin user.
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        (ADMIN_USER,)
    )
    admin_row = cursor.fetchone()

    cursor.execute(
        "SELECT id FROM roles WHERE name = 'admin'"
    )
    admin_role_row = cursor.fetchone()

    if admin_row and admin_role_row:
        cursor.execute(
            """
            INSERT INTO user_roles (user_id, role_id)
            VALUES (?, ?)
            """,
            (admin_row[0], admin_role_row[0])
        )
        connection.commit()

    connection.close()

    normal_token = create_user_session(NORMAL_USER)
    admin_token = create_user_session(ADMIN_USER)

    if normal_token and admin_token:
        print("[PASS] Test sessions created")
    else:
        print("[FAIL] Test sessions were not created")
        failures += 1

    # ============================================================
    # 1. PUBLIC ENDPOINT
    # ============================================================

    print()
    print("[1] PUBLIC API ENDPOINT")

    response = client.get("/health")

    if response.status_code == 200:
        print("[PASS] /health accessible without authentication")
    else:
        print(
            f"[FAIL] /health returned HTTP {response.status_code}"
        )
        failures += 1

    # ============================================================
    # 2. PROTECTED ENDPOINT WITHOUT TOKEN
    # ============================================================

    print()
    print("[2] PROTECTED ENDPOINT WITHOUT TOKEN")

    protected_paths = [
        ("/session", "GET"),
        ("/protected/profile", "GET"),
        ("/protected/profile/read", "GET"),
        ("/admin/users", "GET"),
    ]

    for path, method in protected_paths:

        if method == "GET":
            response = client.get(path)

        if response.status_code == 401:
            print(
                f"[PASS] {method} {path} rejected without token"
            )
        else:
            print(
                f"[FAIL] {method} {path} returned "
                f"HTTP {response.status_code}"
            )
            failures += 1

    # ============================================================
    # 3. PROTECTED ENDPOINT WITH INVALID TOKEN
    # ============================================================

    print()
    print("[3] PROTECTED ENDPOINT WITH INVALID TOKEN")

    invalid_headers = {
        "Authorization": "Bearer INVALID_TOKEN"
    }

    for path in (
        "/session",
        "/protected/profile",
        "/protected/profile/read",
        "/admin/users",
    ):

        response = client.get(
            path,
            headers=invalid_headers
        )

        if response.status_code == 401:
            print(
                f"[PASS] Invalid token rejected by {path}"
            )
        else:
            print(
                f"[FAIL] Invalid token accepted by {path}: "
                f"HTTP {response.status_code}"
            )
            failures += 1

    # ============================================================
    # 4. NORMAL USER → NORMAL PROTECTED RESOURCE
    # ============================================================

    print()
    print("[4] NORMAL USER → PROTECTED RESOURCE")

    normal_headers = {
        "Authorization": f"Bearer {normal_token}"
    }

    response = client.get(
        "/protected/profile",
        headers=normal_headers
    )

    if response.status_code == 200:
        body = response.json()

        if body.get("username") == NORMAL_USER:
            print("[PASS] Normal user accessed protected profile")
        else:
            print("[FAIL] Protected profile identity mismatch")
            failures += 1
    else:
        print(
            f"[FAIL] Normal user denied protected profile: "
            f"HTTP {response.status_code}"
        )
        failures += 1

    # ============================================================
    # 5. NORMAL USER → ADMIN READ
    # ============================================================

    print()
    print("[5] NORMAL USER → ADMIN READ")

    response = client.get(
        "/admin/users",
        headers=normal_headers
    )

    if response.status_code == 403:
        print("[PASS] Normal user denied admin users.read endpoint")
    else:
        print(
            f"[FAIL] Normal user received HTTP "
            f"{response.status_code} from admin endpoint"
        )
        failures += 1

    # ============================================================
    # 6. NORMAL USER → ADMIN DELETE
    # ============================================================

    print()
    print("[6] NORMAL USER → ADMIN DELETE")

    response = client.delete(
        f"/admin/users/{ADMIN_USER}",
        headers=normal_headers
    )

    if response.status_code == 403:
        print("[PASS] Normal user denied admin delete endpoint")
    else:
        print(
            f"[FAIL] Normal user received HTTP "
            f"{response.status_code} from delete endpoint"
        )
        failures += 1

    # Confirm target user still exists.
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        (ADMIN_USER,)
    )

    target_exists = cursor.fetchone() is not None

    connection.close()

    if target_exists:
        print("[PASS] Unauthorized delete did not remove target user")
    else:
        print("[FAIL] Unauthorized request removed target user")
        failures += 1

    # ============================================================
    # 7. NORMAL USER → LEGACY ADMIN ENDPOINT
    # ============================================================

    print()
    print("[7] NORMAL USER → LEGACY ADMIN ENDPOINT")

    response = client.delete(
        "/protected/users",
        headers=normal_headers
    )

    if response.status_code == 403:
        print("[PASS] Normal user denied legacy admin endpoint")
    else:
        print(
            f"[FAIL] Normal user received HTTP "
            f"{response.status_code} from legacy endpoint"
        )
        failures += 1

    # ============================================================
    # 8. ADMIN USER → ADMIN READ
    # ============================================================

    print()
    print("[8] ADMIN USER → ADMIN READ")

    admin_headers = {
        "Authorization": f"Bearer {admin_token}"
    }

    response = client.get(
        "/admin/users",
        headers=admin_headers
    )

    if response.status_code == 200:
        body = response.json()

        if body.get("permission") == "users.read":
            print("[PASS] Admin user granted users.read")
        else:
            print("[FAIL] Admin response permission mismatch")
            failures += 1
    else:
        print(
            f"[FAIL] Admin user denied users.read: "
            f"HTTP {response.status_code}"
        )
        failures += 1

    # ============================================================
    # 9. ADMIN USER → DELETE ENDPOINT
    # ============================================================

    print()
    print("[9] ADMIN USER → ADMIN DELETE")

    # Do NOT delete the admin user itself.
    # Delete only a temporary third user.
    delete_target = "V0811DeleteTarget"

    if not create_registered_user(delete_target):
        print("[FAIL] Could not create delete-target user")
        failures += 1
    else:
        response = client.delete(
            f"/admin/users/{delete_target}",
            headers=admin_headers
        )

        if response.status_code == 200:
            body = response.json()

            if (
                body.get("deleted") is True
                and body.get("username") == delete_target
            ):
                print("[PASS] Admin user granted users.delete")
            else:
                print("[FAIL] Admin delete response invalid")
                failures += 1
        else:
            print(
                f"[FAIL] Admin user denied users.delete: "
                f"HTTP {response.status_code}"
            )
            failures += 1

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (delete_target,)
        )

        still_exists = cursor.fetchone() is not None

        connection.close()

        if not still_exists:
            print("[PASS] Admin deletion removed target user")
        else:
            print("[FAIL] Admin deletion did not remove target user")
            failures += 1

    # ============================================================
    # 10. AUTHORIZATION CANNOT BE OVERRIDDEN BY QUERY PARAMETERS
    # ============================================================

    print()
    print("[10] AUTHORIZATION QUERY PARAMETER MANIPULATION")

    attack_urls = [
        "/admin/users?permission=users.read",
        "/admin/users?role=admin",
        "/admin/users?authorized=true",
        "/admin/users?is_admin=true",
    ]

    for url in attack_urls:

        response = client.get(
            url,
            headers=normal_headers
        )

        if response.status_code == 403:
            print(
                f"[PASS] Authorization remained enforced: {url}"
            )
        else:
            print(
                f"[FAIL] Parameter manipulation bypassed "
                f"authorization: {url}"
            )
            failures += 1

    # ============================================================
    # 11. SESSION IDENTITY BINDING THROUGH HTTP API
    # ============================================================

    print()
    print("[11] HTTP SESSION IDENTITY BINDING")

    response = client.get(
        "/session",
        headers=normal_headers
    )

    if (
        response.status_code == 200
        and response.json().get("username") == NORMAL_USER
    ):
        print("[PASS] Normal HTTP session remains bound to normal user")
    else:
        print("[FAIL] Normal HTTP session identity mismatch")
        failures += 1

    response = client.get(
        "/session",
        headers=admin_headers
    )

    if (
        response.status_code == 200
        and response.json().get("username") == ADMIN_USER
    ):
        print("[PASS] Admin HTTP session remains bound to admin user")
    else:
        print("[FAIL] Admin HTTP session identity mismatch")
        failures += 1

    # ============================================================
    # 12. LOGOUT INVALIDATES HTTP SESSION
    # ============================================================

    print()
    print("[12] HTTP LOGOUT / SESSION INVALIDATION")

    response = client.post(
        "/logout",
        headers=normal_headers
    )

    if response.status_code == 200:
        print("[PASS] HTTP logout succeeded")
    else:
        print(
            f"[FAIL] HTTP logout returned "
            f"HTTP {response.status_code}"
        )
        failures += 1

    response = client.get(
        "/session",
        headers=normal_headers
    )

    if response.status_code == 401:
        print("[PASS] Logged-out HTTP session rejected")
    else:
        print(
            f"[FAIL] Logged-out session remained valid: "
            f"HTTP {response.status_code}"
        )
        failures += 1

    normal_token = None

finally:

    print()
    print("[CLEANUP] Revoking remaining test sessions")

    if normal_token:
        try:
            logout(normal_token)
        except Exception:
            pass

    if admin_token:
        try:
            logout(admin_token)
        except Exception:
            pass

    cleanup()

print()
print("=" * 70)

if failures == 0:
    print("V0.8.11 API SECURITY BOUNDARY TEST PASSED")
else:
    print(
        f"V0.8.11 API SECURITY BOUNDARY TEST FAILED: "
        f"{failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
