import os
import requests
import sqlite3

BASE = "http://127.0.0.1:8000"

USERNAME = "V07Normal3"
WRONG_PASSWORD = os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")

DB = "data/dpas.db"


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


def reset_state():
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET failed_attempts = 0,
            locked_until = NULL
        WHERE username = ?
    """, (USERNAME,))

    connection.commit()
    connection.close()


print("=" * 70)
print("DPAS V0.8.1 /auth/verify LOCKOUT BYPASS TEST")
print("=" * 70)

print("\n[1] RESET ACCOUNT")

reset_state()

print(
    "STATE:",
    get_state()
)

print("\n[2] CREATE AUTH CHALLENGE")

response = requests.post(
    f"{BASE}/auth/challenge",
    json={
        "username": USERNAME
    }
)

print(
    "STATUS:",
    response.status_code
)

print(
    "BODY:",
    response.text
)

if response.status_code != 200:
    print("[ABORT] Challenge creation failed")
    raise SystemExit(1)

data = response.json()

challenge = data["challenge"]

print(
    "[PASS] Challenge obtained"
)

print("\n[3] SUBMIT INVALID SIGNATURE")

for attempt in range(1, 8):

    response = requests.post(
        f"{BASE}/auth/verify",
        json={
            "username": USERNAME,
            "challenge": challenge,
            "signature": "INVALID_SIGNATURE"
        }
    )

    print(
        f"ATTEMPT {attempt}:",
        response.status_code,
        response.text
    )

    print(
        "ACCOUNT STATE:",
        get_state()
    )

print("\n[4] RESULT")

failed_attempts, locked_until = get_state()

print(
    "FAILED ATTEMPTS:",
    failed_attempts
)

print(
    "LOCKED UNTIL:",
    locked_until
)

if failed_attempts == 0 and locked_until is None:

    print(
        "[FAIL] /auth/verify does not update lockout state"
    )

else:

    print(
        "[PASS] /auth/verify affects lockout state"
    )

print("\n[5] CLEANUP")

reset_state()

print(
    "FINAL STATE:",
    get_state()
)

print("=" * 70)
print("TEST FINISHED")
print("=" * 70)

