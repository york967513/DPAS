import requests
import sqlite3
import concurrent.futures
import os

BASE = "http://127.0.0.1:8000"
USERNAME = "V085LockoutRaceTest"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")
DB = "data/dpas.db"
KEY_PATH = f"data/client_keys/{USERNAME}.key"

TOTAL_REQUESTS = 10


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

    if os.path.exists(KEY_PATH):
        os.remove(KEY_PATH)


def get_account_state():

    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    row = cursor.execute("""
        SELECT failed_attempts, locked_until
        FROM users
        WHERE username = ?
    """, (USERNAME,)).fetchone()

    connection.close()

    return row


print("=" * 70)
print("DPAS V0.8.5 CONCURRENT LOCKOUT RACE TEST")
print("=" * 70)


# ========================================
# 1. RESET
# ========================================

print("\n[1] RESET TEST ACCOUNT")

cleanup()

print("[PASS] Previous test state removed")


# ========================================
# 2. CREATE USER
# ========================================

print("\n[2] CREATE TEST USER")

from app.auth import register_user
from app.client_storage import save_private_key

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


# ========================================
# 3. CREATE CHALLENGE
# ========================================

print("\n[3] CREATE AUTH CHALLENGE")

response = requests.post(
    f"{BASE}/auth/challenge",
    json={
        "username": USERNAME
    }
)

print("STATUS:", response.status_code)
print("BODY:", response.text)

if response.status_code != 200:
    print("[FAIL] Challenge creation failed")
    cleanup()
    raise SystemExit(1)

challenge = response.json()["challenge"]

print("[PASS] Challenge obtained")
print("CHALLENGE:", challenge)


# ========================================
# 4. SEND CONCURRENT INVALID SIGNATURES
# ========================================

print("\n[4] SEND CONCURRENT INVALID SIGNATURES")

print("TOTAL REQUESTS:", TOTAL_REQUESTS)

INVALID_SIGNATURE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

def invalid_verify(index):

    try:

        response = requests.post(
            f"{BASE}/auth/verify",
            json={
                "username": USERNAME,
                "challenge": challenge,
                "signature": INVALID_SIGNATURE
            },
            timeout=10
        )

        return (
            index,
            response.status_code,
            response.text
        )

    except Exception as e:

        return (
            index,
            "EXCEPTION",
            f"{type(e).__name__}: {e}"
        )


with concurrent.futures.ThreadPoolExecutor(
    max_workers=TOTAL_REQUESTS
) as executor:

    futures = [
        executor.submit(
            invalid_verify,
            i + 1
        )
        for i in range(TOTAL_REQUESTS)
    ]

    results = [
        future.result()
        for future in futures
    ]


# ========================================
# 5. RESULTS
# ========================================

print("\n[5] CONCURRENT RESULTS")

failure_401 = 0
other = 0

for index, status, body in sorted(results):

    print(
        f"REQUEST {index}:",
        status,
        body
    )

    if status == 401:
        failure_401 += 1
    else:
        other += 1


print()
print("HTTP 401:", failure_401)
print("OTHER:", other)


# ========================================
# 6. CHECK ACCOUNT STATE
# ========================================

print("\n[6] CHECK ACCOUNT LOCKOUT STATE")

state = get_account_state()

print("ACCOUNT STATE:", state)

if state is None:
    print("[FAIL] Test account disappeared")
    cleanup()
    raise SystemExit(1)

failed_attempts, locked_until = state

print("FAILED ATTEMPTS:", failed_attempts)
print("LOCKED UNTIL:", locked_until)


# ========================================
# 7. VERIFY LOCKOUT
# ========================================

print("\n[7] LOCKOUT ANALYSIS")

if failed_attempts >= 5 and locked_until is not None:

    print("[PASS] Account reached lockout threshold")
    print("[PASS] Account is locked")

else:

    print("[FAIL] Concurrent failures did not produce expected lockout")
    print(
        "[FAIL] Expected failed_attempts >= 5 and locked_until != NULL"
    )


# ========================================
# 8. ATTEMPT NEW CHALLENGE WHILE LOCKED
# ========================================

print("\n[8] ATTEMPT NEW CHALLENGE WHILE LOCKED")

locked_challenge_response = requests.post(
    f"{BASE}/auth/challenge",
    json={
        "username": USERNAME
    }
)

print(
    "STATUS:",
    locked_challenge_response.status_code
)

print(
    "BODY:",
    locked_challenge_response.text
)

if locked_challenge_response.status_code != 200:

    print("[PASS] Locked account cannot obtain new challenge")

else:

    print("[FAIL] Locked account obtained a new challenge")


# ========================================
# 9. ATTEMPT LOGIN WITH EXISTING CHALLENGE
# ========================================

print("\n[9] ATTEMPT AUTHENTICATION WHILE LOCKED")

locked_verify_response = requests.post(
    f"{BASE}/auth/verify",
    json={
        "username": USERNAME,
        "challenge": challenge,
        "signature": INVALID_SIGNATURE
    }
)

print(
    "STATUS:",
    locked_verify_response.status_code
)

print(
    "BODY:",
    locked_verify_response.text
)

if locked_verify_response.status_code == 401:

    print("[PASS] Authentication rejected while account is locked")

else:

    print("[FAIL] Authentication was accepted while account is locked")


# ========================================
# 10. FINAL STATE
# ========================================

print("\n[10] FINAL ACCOUNT STATE")

final_state = get_account_state()

print("FINAL STATE:", final_state)

if final_state is not None:

    final_failed, final_locked = final_state

    print("FAILED ATTEMPTS:", final_failed)
    print("LOCKED UNTIL:", final_locked)

    if final_locked is not None:
        print("[PASS] Lockout remains active")

    else:
        print("[FAIL] Lockout disappeared unexpectedly")


# ========================================
# 11. CLEANUP
# ========================================

print("\n[11] CLEANUP")

cleanup()

print("[PASS] Test account removed")

print()
print("=" * 70)
print("V0.8.5 CONCURRENT LOCKOUT RACE TEST FINISHED")
print("=" * 70)

