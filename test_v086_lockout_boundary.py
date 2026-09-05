import os
import requests
import sqlite3
import time

from app.auth import register_user
from app.client_storage import save_private_key
from app.database import get_user
from app.client_auth import create_client_signature


BASE = "http://127.0.0.1:8000"
USERNAME = "V086LockoutBoundaryTest"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

DB = "data/dpas.db"


def cleanup():
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM challenges WHERE username = ?",
        (USERNAME,)
    )

    cursor.execute(
        "DELETE FROM sessions WHERE username = ?",
        (USERNAME,)
    )

    cursor.execute(
        "DELETE FROM users WHERE username = ?",
        (USERNAME,)
    )

    connection.commit()
    connection.close()


def get_state():
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    row = cursor.execute("""
        SELECT failed_attempts, locked_until
        FROM users
        WHERE username = ?
    """, (USERNAME,)).fetchone()

    connection.close()

    return row


def create_challenge():
    return requests.post(
        f"{BASE}/auth/challenge",
        json={"username": USERNAME}
    )


def verify(challenge, signature):
    return requests.post(
        f"{BASE}/auth/verify",
        json={
            "username": USERNAME,
            "challenge": challenge,
            "signature": signature
        }
    )


print("=" * 70)
print("DPAS V0.8.6 LOCKOUT BOUNDARY / RECOVERY TEST")
print("=" * 70)


print("\n[1] RESET TEST ACCOUNT")

cleanup()

print("[PASS] Previous test state removed")


print("\n[2] CREATE TEST USER")

registration = register_user(
    USERNAME,
    PASSWORD
)

if registration is None:
    print("[FAIL] Could not create test user")
    raise SystemExit(1)

save_private_key(
    USERNAME,
    registration["encrypted_private_key"]
)

print("[PASS] Test user created")
print("[PASS] Client private key saved")
print("USERNAME:", USERNAME)


print("\n[3] CREATE AUTH CHALLENGE")

response = create_challenge()

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code != 200:
    print("[FAIL] Could not create initial challenge")
    cleanup()
    raise SystemExit(1)

challenge = response.json()["challenge"]

print("[PASS] Challenge obtained")


print("\n[4] GET AUTH SALT")

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    cleanup()
    raise SystemExit(1)

auth_salt = user[6]

print("[PASS] Auth salt obtained")


print("\n[5] SEND FOUR INVALID SIGNATURES")

invalid_signature = "INVALID_SIGNATURE"

for i in range(1, 5):

    response = verify(
        challenge,
        invalid_signature
    )

    print(
        f"ATTEMPT {i}:",
        response.status_code,
        response.text
    )

    if response.status_code != 401:
        print(
            f"[FAIL] Attempt {i} did not return HTTP 401"
        )
        cleanup()
        raise SystemExit(1)

state = get_state()

print("ACCOUNT STATE:", state)

if state is None:
    print("[FAIL] Account disappeared")
    cleanup()
    raise SystemExit(1)

failed_attempts, locked_until = state

if failed_attempts == 4 and locked_until is None:
    print("[PASS] Four failures did not lock account")
else:
    print(
        "[FAIL] Unexpected state after four failures:",
        state
    )
    cleanup()
    raise SystemExit(1)


print("\n[6] FIFTH INVALID SIGNATURE")

response = verify(
    challenge,
    invalid_signature
)

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code != 401:
    print("[FAIL] Fifth invalid authentication was not rejected")
    cleanup()
    raise SystemExit(1)

state = get_state()

print("ACCOUNT STATE:", state)

if state is None:
    print("[FAIL] Account disappeared")
    cleanup()
    raise SystemExit(1)

failed_attempts, locked_until = state

if failed_attempts >= 5 and locked_until is not None:
    print("[PASS] Account reached lockout threshold")
else:
    print("[FAIL] Account was not locked")
    cleanup()
    raise SystemExit(1)


print("\n[7] ATTEMPT NEW CHALLENGE WHILE LOCKED")

response = create_challenge()

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code == 401:
    print("[PASS] Locked account cannot obtain new challenge")
else:
    print(
        "[FAIL] Unexpected challenge response while locked"
    )


print("\n[8] CREATE VALID SIGNATURE FOR LOCKOUT TEST")

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    cleanup()
    raise SystemExit(1)

auth_salt = user[6]

try:

    valid_signature = create_client_signature(
        USERNAME,
        PASSWORD,
        auth_salt,
        challenge
    )

    print("[PASS] Valid signature created")

except Exception as e:

    print("[FAIL] Could not create valid signature")
    print(type(e).__name__, str(e))

    cleanup()
    raise SystemExit(1)


print("\n[9] ATTEMPT VALID AUTHENTICATION WHILE LOCKED")

response = verify(
    challenge,
    valid_signature
)

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code == 401:
    print("[PASS] Valid authentication rejected during lockout")
else:
    print("[FAIL] Valid authentication was accepted while locked")


print("\n[10] WAIT FOR LOCKOUT TO EXPIRE")

state = get_state()

print("CURRENT STATE:", state)

if state is None:
    print("[FAIL] Account disappeared")
    cleanup()
    raise SystemExit(1)

locked_until = state[1]

if locked_until is None:
    print("[FAIL] locked_until is missing")
    cleanup()
    raise SystemExit(1)

from datetime import datetime, timezone

lock_time = datetime.fromisoformat(
    locked_until
)

now = datetime.now(timezone.utc)

wait_seconds = (
    lock_time - now
).total_seconds()

if wait_seconds > 0:
    print(
        "WAITING:",
        round(wait_seconds, 2),
        "seconds"
    )

    time.sleep(
        wait_seconds + 1
    )

print("[PASS] Lockout period elapsed")


print("\n[11] CREATE NEW CHALLENGE AFTER LOCKOUT")

response = create_challenge()

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code != 200:
    print(
        "[FAIL] New challenge was not available after lockout"
    )
    cleanup()
    raise SystemExit(1)

new_challenge = response.json()["challenge"]

print("[PASS] New challenge created")


print("\n[12] CREATE VALID SIGNATURE AFTER LOCKOUT")

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    cleanup()
    raise SystemExit(1)

auth_salt = user[6]

try:

    new_signature = create_client_signature(
        USERNAME,
        PASSWORD,
        auth_salt,
        new_challenge
    )

    print("[PASS] New valid signature created")

except Exception as e:

    print("[FAIL] Could not create new signature")
    print(type(e).__name__, str(e))

    cleanup()
    raise SystemExit(1)


print("\n[13] AUTHENTICATE AFTER LOCKOUT")

response = verify(
    new_challenge,
    new_signature
)

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code == 200:
    print("[PASS] Authentication restored after lockout")
else:
    print("[FAIL] Authentication did not recover")
    cleanup()
    raise SystemExit(1)


print("\n[14] CHECK FINAL ACCOUNT STATE")

state = get_state()

print("FINAL STATE:", state)

if state is None:
    print("[FAIL] Account disappeared")
    cleanup()
    raise SystemExit(1)

failed_attempts, locked_until = state

if failed_attempts == 0 and locked_until is None:
    print("[PASS] Failed attempts reset")
    print("[PASS] Lockout state cleared")
else:
    print(
        "[FAIL] Lockout state was not fully cleared"
    )


print("\n[15] CLEANUP")

cleanup()

print("[PASS] Test account removed")

print()
print("=" * 70)
print("V0.8.6 LOCKOUT BOUNDARY / RECOVERY TEST FINISHED")
print("=" * 70)

