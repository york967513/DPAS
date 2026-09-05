import os
import sys
import sqlite3
from datetime import datetime, timezone, timedelta

sys.path.insert(0, r"C:\DPAS")

from app.auth import register_user
from app.client_storage import save_private_key
from app.database import get_connection, get_user, get_challenge
from app.server_auth import (
    create_login_challenge,
    verify_login_response,
    CHALLENGE_TTL_SECONDS
)
from app.key_manager import decrypt_private_key
from app.protocol import sign_challenge


USERNAME = "V087ChallengeTTL"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


def cleanup():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM audit_log WHERE username = ?",
        (USERNAME,)
    )

    cursor.execute(
        "DELETE FROM challenges WHERE username = ?",
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


def set_challenge_created_at(challenge, created_at):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE challenges
        SET created_at = ?
        WHERE username = ?
          AND challenge = ?
        """,
        (
            created_at,
            USERNAME,
            challenge
        )
    )

    connection.commit()
    connection.close()


def get_audit_events():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT event_type, action, result, details
        FROM audit_log
        WHERE username = ?
        ORDER BY id DESC
        """,
        (USERNAME,)
    )

    rows = cursor.fetchall()
    connection.close()

    return rows


print()
print("=== V0.8.7 Challenge TTL / Expiration Test ===")
print()

cleanup()

print("[1] Registering test user...")

result = register_user(
    USERNAME,
    PASSWORD
)

if result is None:
    print("FAIL: registration failed")
    cleanup()
    raise SystemExit(1)

save_private_key(
    USERNAME,
    result["encrypted_private_key"]
)

print("PASS: user registered and client key saved")
print()


# ---------------------------------------------------------
# TEST 1: Challenge younger than TTL
# ---------------------------------------------------------

print("[2] Creating fresh challenge...")

request = create_login_challenge(USERNAME)

if request is None:
    print("FAIL: challenge creation failed")
    cleanup()
    raise SystemExit(1)

challenge = request["challenge"]

print("PASS: challenge created")
print()


# Load private key and create valid signature.
user_key = result["encrypted_private_key"]

from app.password import derive_key

private_key = decrypt_private_key(
    user_key,
    PASSWORD,
    get_user(USERNAME)[6]
)

signature = sign_challenge(
    private_key,
    challenge
)

print("[3] Testing fresh challenge...")

valid = verify_login_response(
    USERNAME,
    challenge,
    signature
)

if not valid:
    print("FAIL: fresh challenge was rejected")
    cleanup()
    raise SystemExit(1)

print("PASS: fresh challenge accepted")
print()


# ---------------------------------------------------------
# TEST 2: Challenge older than TTL
# ---------------------------------------------------------

print("[4] Creating second challenge for expiration test...")

request = create_login_challenge(USERNAME)

if request is None:
    print("FAIL: second challenge creation failed")
    cleanup()
    raise SystemExit(1)

expired_challenge = request["challenge"]

expired_signature = sign_challenge(
    private_key,
    expired_challenge
)

expired_time = (
    datetime.now(timezone.utc)
    - timedelta(seconds=CHALLENGE_TTL_SECONDS + 1)
).isoformat()

set_challenge_created_at(
    expired_challenge,
    expired_time
)

print(
    f"Challenge timestamp moved to "
    f"{CHALLENGE_TTL_SECONDS + 1} seconds ago"
)

print("[5] Verifying expired challenge...")

expired_result = verify_login_response(
    USERNAME,
    expired_challenge,
    expired_signature
)

if expired_result:
    print("FAIL: expired challenge was accepted")
    cleanup()
    raise SystemExit(1)

print("PASS: expired challenge rejected")
print()


# ---------------------------------------------------------
# TEST 3: Challenge remains unused after expiration
# ---------------------------------------------------------

stored = get_challenge(
    USERNAME,
    expired_challenge
)

if stored is None:
    print("FAIL: expired challenge disappeared unexpectedly")
    cleanup()
    raise SystemExit(1)

if stored[4] != 0:
    print(
        f"FAIL: expired challenge has unexpected used state: "
        f"{stored[4]}"
    )
    cleanup()
    raise SystemExit(1)

print("PASS: expired challenge remains unused")
print()


# ---------------------------------------------------------
# TEST 4: Audit log
# ---------------------------------------------------------

print("[6] Checking audit log...")

events = get_audit_events()

expired_event_found = any(
    event[0] == "AUTHENTICATION"
    and event[1] == "LOGIN"
    and event[2] == "FAILURE"
    and event[3] == "Challenge expired"
    for event in events
)

if not expired_event_found:
    print("FAIL: 'Challenge expired' audit event not found")
    cleanup()
    raise SystemExit(1)

print("PASS: Challenge expired audit event recorded")
print()


# ---------------------------------------------------------
# TEST 5: Failed-attempt counter
# ---------------------------------------------------------

user = get_user(USERNAME)

if user is None:
    print("FAIL: user disappeared")
    cleanup()
    raise SystemExit(1)

failed_attempts = user[4]

if failed_attempts != 1:
    print(
        f"FAIL: expected failed_attempts=1, "
        f"got {failed_attempts}"
    )
    cleanup()
    raise SystemExit(1)

print("PASS: expired challenge counted as authentication failure")
print()


# ---------------------------------------------------------
# Cleanup
# ---------------------------------------------------------

print("[7] Cleaning up...")

cleanup()

print("PASS: cleanup completed")
print()

print("=== V0.8.7 PASSED ===")
print()

