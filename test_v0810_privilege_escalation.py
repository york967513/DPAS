import sqlite3

from app.authorization import (
    require_auth,
    require_permission,
    require_user,
)
from app.database import get_connection
from app.session_manager import (
    create_user_session,
    logout,
)


USER_A = "V0810Normal"
USER_B = "V0810Admin"

NORMAL_ROLE = "user"
ADMIN_ROLE = "admin"


def cleanup():
    connection = get_connection()
    cursor = connection.cursor()

    # Remove test sessions first.
    cursor.execute(
        "DELETE FROM sessions WHERE username IN (?, ?)",
        (USER_A, USER_B)
    )

    # Remove test users/roles while preserving audit history.
    cursor.execute(
        "DELETE FROM user_roles WHERE user_id IN "
        "(SELECT id FROM users WHERE username IN (?, ?))",
        (USER_A, USER_B)
    )

    cursor.execute(
        "DELETE FROM users WHERE username IN (?, ?)",
        (USER_A, USER_B)
    )

    cursor.execute(
        "DELETE FROM audit_log WHERE username IN (?, ?)",
        (USER_A, USER_B)
    )

    connection.commit()
    connection.close()


def create_test_user(username, role):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO users (
            username,
            password_hash,
            created_at,
            failed_attempts,
            locked_until,
            auth_salt,
            public_key
        )
        VALUES (?, ?, datetime('now'), 0, NULL, ?, ?)
        """,
        (
            username,
            b"V0810_TEST_PASSWORD_HASH",
            b"V0810_TEST_SALT",
            b"V0810_TEST_PUBLIC_KEY",
        )
    )

    user_id = cursor.lastrowid

    cursor.execute(
        """
        SELECT id
        FROM roles
        WHERE name = ?
        """,
        (role,)
    )

    role_row = cursor.fetchone()

    if role_row is None:
        connection.rollback()
        connection.close()
        raise RuntimeError(f"Role not found: {role}")

    role_id = role_row[0]

    cursor.execute(
        """
        INSERT INTO user_roles (
            user_id,
            role_id
        )
        VALUES (?, ?)
        """,
        (user_id, role_id)
    )

    connection.commit()
    connection.close()


print("=" * 70)
print("DPAS V0.8.10 PRIVILEGE ESCALATION / AUTHORIZATION BOUNDARY TEST")
print("=" * 70)

cleanup()

failures = 0

try:

    # ============================================================
    # TEST USERS
    # ============================================================

    print()
    print("[SETUP] Creating isolated test users")

    create_test_user(USER_A, NORMAL_ROLE)
    create_test_user(USER_B, ADMIN_ROLE)

    normal_token = create_user_session(USER_A)
    admin_token = create_user_session(USER_B)

    if normal_token and admin_token:
        print("[PASS] Test sessions created")
    else:
        print("[FAIL] Test session creation failed")
        failures += 1

    # ============================================================
    # 1. AUTHENTICATION BOUNDARY
    # ============================================================

    print()
    print("[1] AUTHENTICATION BOUNDARY")

    if require_auth(normal_token) == USER_A:
        print("[PASS] Normal token authenticated as normal user")
    else:
        print("[FAIL] Normal token authentication mismatch")
        failures += 1

    if require_auth(admin_token) == USER_B:
        print("[PASS] Admin token authenticated as admin user")
    else:
        print("[FAIL] Admin token authentication mismatch")
        failures += 1

    if require_auth("INVALID_TOKEN") is None:
        print("[PASS] Invalid token rejected")
    else:
        print("[FAIL] Invalid token accepted")
        failures += 1

    # ============================================================
    # 2. NORMAL USER CANNOT OBTAIN ADMIN PERMISSION
    # ============================================================

    print()
    print("[2] NORMAL USER → ADMIN PERMISSION")

    if not require_permission(
        normal_token,
        "users.delete"
    ):
        print("[PASS] Normal user denied users.delete")
    else:
        print("[FAIL] Normal user received users.delete")
        failures += 1

    if not require_permission(
        normal_token,
        "admin"
    ):
        print("[PASS] Normal user denied admin permission")
    else:
        print("[FAIL] Normal user received admin permission")
        failures += 1

    # ============================================================
    # 3. ADMIN USER RETAINS ADMIN PERMISSION
    # ============================================================

    print()
    print("[3] ADMIN USER → ADMIN PERMISSION")

    if require_permission(
        admin_token,
        "users.delete"
    ):
        print("[PASS] Admin user granted users.delete")
    else:
        print("[FAIL] Admin user denied users.delete")
        failures += 1

    # ============================================================
    # 4. UNKNOWN PERMISSION
    # ============================================================

    print()
    print("[4] UNKNOWN PERMISSION")

    if not require_permission(
        admin_token,
        "permission.that.does.not.exist"
    ):
        print("[PASS] Unknown permission denied")
    else:
        print("[FAIL] Unknown permission granted")
        failures += 1

    if not require_permission(
        normal_token,
        "permission.that.does.not.exist"
    ):
        print("[PASS] Unknown permission denied for normal user")
    else:
        print("[FAIL] Unknown permission granted to normal user")
        failures += 1

    # ============================================================
    # 5. USER BOUNDARY
    # ============================================================

    print()
    print("[5] USER-BOUND AUTHORIZATION")

    if require_user(
        normal_token,
        USER_A
    ):
        print("[PASS] Normal user can access own identity")
    else:
        print("[FAIL] Normal user denied own identity")
        failures += 1

    if not require_user(
        normal_token,
        USER_B
    ):
        print("[PASS] Normal user denied admin identity")
    else:
        print("[FAIL] Normal user accessed admin identity")
        failures += 1

    if require_user(
        admin_token,
        USER_B
    ):
        print("[PASS] Admin user can access own identity")
    else:
        print("[FAIL] Admin user denied own identity")
        failures += 1

    # ============================================================
    # 6. PERMISSION PARAMETER MANIPULATION
    # ============================================================

    print()
    print("[6] PERMISSION PARAMETER MANIPULATION")

    injected_permissions = [
        "admin",
        "users.delete",
        "role=admin",
        "permission=users.delete",
        "*",
        "admin,users.delete",
    ]

    for permission in injected_permissions:

        result = require_permission(
            normal_token,
            permission
        )

        if result:
            print(
                f"[FAIL] Permission injection granted: {permission}"
            )
            failures += 1
        else:
            print(
                f"[PASS] Permission denied: {permission}"
            )

    # ============================================================
    # 7. TOKEN + ADMIN PERMISSION COMBINATION
    # ============================================================

    print()
    print("[7] INVALID TOKEN + ADMIN PERMISSION")

    if not require_permission(
        "INVALID_TOKEN",
        "users.delete"
    ):
        print("[PASS] Invalid token cannot obtain admin permission")
    else:
        print("[FAIL] Invalid token obtained admin permission")
        failures += 1

    # ============================================================
    # 8. TOKEN USERNAME SWITCH
    # ============================================================

    print()
    print("[8] TOKEN USERNAME SWITCH")

    if not require_user(
        normal_token,
        USER_B
    ):
        print("[PASS] Normal token cannot switch to admin identity")
    else:
        print("[FAIL] Normal token switched identity")
        failures += 1

    if require_user(
        admin_token,
        USER_B
    ):
        print("[PASS] Admin token remains bound to admin identity")
    else:
        print("[FAIL] Admin token identity mismatch")
        failures += 1

    # ============================================================
    # 9. AUDIT LOG AUTHORIZATION EVENTS
    # ============================================================

    print()
    print("[9] AUTHORIZATION AUDIT EVENTS")

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM audit_log
        WHERE username = ?
          AND event_type = 'AUTHORIZATION'
          AND action = 'ACCESS_DENIED'
        """,
        (USER_A,)
    )

    denied_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM audit_log
        WHERE username = ?
          AND event_type = 'AUTHORIZATION'
          AND action = 'ACCESS_GRANTED'
        """,
        (USER_B,)
    )

    granted_count = cursor.fetchone()[0]

    connection.close()

    if denied_count > 0:
        print(
            f"[PASS] Authorization denials recorded: {denied_count}"
        )
    else:
        print("[FAIL] Authorization denial was not audited")
        failures += 1

    if granted_count > 0:
        print(
            f"[PASS] Authorization grants recorded: {granted_count}"
        )
    else:
        print("[FAIL] Authorization grant was not audited")
        failures += 1

finally:

    # ============================================================
    # CLEANUP
    # ============================================================

    print()
    print("[CLEANUP] Revoking test sessions")

    try:
        if "normal_token" in locals():
            logout(normal_token)
    except Exception:
        pass

    try:
        if "admin_token" in locals():
            logout(admin_token)
    except Exception:
        pass

    print("[CLEANUP] Removing test users and audit records")

    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.10 PRIVILEGE ESCALATION TEST PASSED")
else:
    print(
        f"V0.8.10 PRIVILEGE ESCALATION TEST FAILED: "
        f"{failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
