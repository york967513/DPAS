import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, r"C:\DPAS")

from app.database import (
    get_connection,
    get_session
)

from app.session_manager import (
    create_user_session,
    validate_session,
    get_session_username,
    logout,
    _hash_token
)


USERNAME = "V088SessionTTL"


def cleanup():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM audit_log WHERE username = ?",
        (USERNAME,)
    )

    cursor.execute(
        "DELETE FROM sessions WHERE username = ?",
        (USERNAME,)
    )

    cursor.execute(
        "DELETE FROM user_roles WHERE user_id IN "
        "(SELECT id FROM users WHERE username = ?)",
        (USERNAME,)
    )

    cursor.execute(
        "DELETE FROM users WHERE username = ?",
        (USERNAME,)
    )

    connection.commit()
    connection.close()


def set_expires_at(token, expires_at):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE sessions
        SET expires_at = ?
        WHERE token_hash = ?
        """,
        (
            expires_at,
            _hash_token(token)
        )
    )

    connection.commit()
    connection.close()


print()
print("=== V0.8.8 Session TTL / Expiration Boundary Test ===")
print()

cleanup()

# ---------------------------------------------------------
# TEST 1: Create valid session
# ---------------------------------------------------------

print("[1] Creating authenticated session...")

token = create_user_session(USERNAME)

if not token:
    print("FAIL: session token was not created")
    cleanup()
    raise SystemExit(1)

session = get_session(
    _hash_token(token)
)

if session is None:
    print("FAIL: session was not stored")
    cleanup()
    raise SystemExit(1)

if session[5] != 0:
    print(
        f"FAIL: new session has revoked={session[5]}"
    )
    cleanup()
    raise SystemExit(1)

print("PASS: session created and active")
print()


# ---------------------------------------------------------
# TEST 2: Active session is valid
# ---------------------------------------------------------

print("[2] Validating active session...")

if not validate_session(token):
    print("FAIL: active session rejected")
    cleanup()
    raise SystemExit(1)

username = get_session_username(token)

if username != USERNAME:
    print(
        f"FAIL: expected username {USERNAME}, "
        f"got {username}"
    )
    cleanup()
    raise SystemExit(1)

print("PASS: active session accepted")
print("PASS: session username resolved correctly")
print()


# ---------------------------------------------------------
# TEST 3: Expired session
# ---------------------------------------------------------

print("[3] Moving session expiration into the past...")

expired_at = (
    datetime.now(timezone.utc)
    - timedelta(seconds=1)
).isoformat()

set_expires_at(
    token,
    expired_at
)

print("PASS: expires_at moved into the past")
print()

print("[4] Validating expired session...")

if validate_session(token):
    print("FAIL: expired session was accepted")
    cleanup()
    raise SystemExit(1)

print("PASS: expired session rejected")
print()


# ---------------------------------------------------------
# TEST 4: Expired session cannot resolve username
# ---------------------------------------------------------

print("[5] Checking username lookup for expired session...")

expired_username = get_session_username(token)

if expired_username is not None:
    print(
        "FAIL: expired session returned username: "
        f"{expired_username}"
    )
    cleanup()
    raise SystemExit(1)

print("PASS: expired session cannot resolve username")
print()


# ---------------------------------------------------------
# TEST 5: Exact expiration boundary
# ---------------------------------------------------------

print("[6] Testing exact expiration boundary...")

boundary_token = create_user_session(USERNAME)

boundary_expires_at = (
    datetime.now(timezone.utc)
).isoformat()

set_expires_at(
    boundary_token,
    boundary_expires_at
)

if validate_session(boundary_token):
    print("FAIL: session at expiration boundary was accepted")
    cleanup()
    raise SystemExit(1)

print(
    "PASS: session at expiration boundary rejected "
    "(now >= expires_at)"
)
print()


# ---------------------------------------------------------
# TEST 6: Revocation still works
# ---------------------------------------------------------

print("[7] Creating another active session...")

revocation_token = create_user_session(USERNAME)

if not validate_session(revocation_token):
    print("FAIL: fresh session is not valid")
    cleanup()
    raise SystemExit(1)

print("PASS: fresh session is valid")
print()

print("[8] Revoking session...")

if not logout(revocation_token):
    print("FAIL: logout/revocation failed")
    cleanup()
    raise SystemExit(1)

if validate_session(revocation_token):
    print("FAIL: revoked session is still valid")
    cleanup()
    raise SystemExit(1)

print("PASS: revoked session rejected")
print()


# ---------------------------------------------------------
# TEST 7: Database state
# ---------------------------------------------------------

print("[9] Checking database state...")

revoked_session = get_session(
    _hash_token(revocation_token)
)

if revoked_session is None:
    print("FAIL: revoked session disappeared")
    cleanup()
    raise SystemExit(1)

if revoked_session[5] != 1:
    print(
        f"FAIL: expected revoked=1, "
        f"got {revoked_session[5]}"
    )
    cleanup()
    raise SystemExit(1)

print("PASS: revoked session remains stored with revoked=1")
print()


# ---------------------------------------------------------
# Cleanup
# ---------------------------------------------------------

print("[10] Cleaning up...")

cleanup()

print("PASS: cleanup completed")
print()

print("=== V0.8.8 PASSED ===")
print()
