import requests
import sqlite3
import concurrent.futures
import os

BASE = "http://127.0.0.1:8000"
USERNAME = "V084RaceTest"
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


def db_challenge_state(challenge):
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    row = cursor.execute("""
        SELECT used
        FROM challenges
        WHERE username = ?
          AND challenge = ?
    """, (
        USERNAME,
        challenge
    )).fetchone()

    connection.close()

    return row


print("=" * 70)
print("DPAS V0.8.4 CONCURRENT CHALLENGE RACE TEST")
print("=" * 70)


# ========================================
# 1. CLEANUP
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

print("\n[3] CREATE SINGLE AUTH CHALLENGE")

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
# 4. CREATE VALID SIGNATURE
# ========================================

print("\n[4] CREATE VALID SIGNATURE")

from app.database import get_user
from app.client_auth import create_client_signature

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    cleanup()
    raise SystemExit(1)

auth_salt = user[6]

try:
    signature = create_client_signature(
        USERNAME,
        PASSWORD,
        auth_salt,
        challenge
    )
except Exception as e:
    print("[FAIL] Could not create signature")
    print(type(e).__name__, str(e))
    cleanup()
    raise SystemExit(1)

print("[PASS] Valid signature created")
print("SIGNATURE LENGTH:", len(signature))


# ========================================
# 5. VERIFY INITIAL STATE
# ========================================

print("\n[5] CHECK INITIAL CHALLENGE STATE")

state_before = db_challenge_state(challenge)

print("CHALLENGE STATE:", state_before)

if state_before == (0,):
    print("[PASS] Challenge is unused")
else:
    print("[FAIL] Challenge is not in expected unused state")
    cleanup()
    raise SystemExit(1)


# ========================================
# 6. CONCURRENT VERIFY
# ========================================

print("\n[6] SEND CONCURRENT /auth/verify REQUESTS")

print("TOTAL REQUESTS:", TOTAL_REQUESTS)

def verify_request(index):

    try:

        response = requests.post(
            f"{BASE}/auth/verify",
            json={
                "username": USERNAME,
                "challenge": challenge,
                "signature": signature
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
            verify_request,
            i + 1
        )
        for i in range(TOTAL_REQUESTS)
    ]

    results = [
        future.result()
        for future in futures
    ]


# ========================================
# 7. DISPLAY RESULTS
# ========================================

print("\n[7] CONCURRENT RESULTS")

success_count = 0
failure_count = 0
exception_count = 0

for index, status, body in sorted(results):

    print(
        f"REQUEST {index}:",
        status,
        body
    )

    if status == 200:
        success_count += 1

    elif status == 401:
        failure_count += 1

    else:
        exception_count += 1


print()
print("SUCCESS (200):", success_count)
print("AUTH FAILURE (401):", failure_count)
print("OTHER / EXCEPTION:", exception_count)


# ========================================
# 8. CHECK CHALLENGE STATE
# ========================================

print("\n[8] CHECK CHALLENGE STATE AFTER RACE")

state_after = db_challenge_state(challenge)

print("CHALLENGE STATE:", state_after)

if state_after == (1,):
    print("[PASS] Challenge was consumed")
else:
    print("[FAIL] Challenge was not consumed correctly")


# ========================================
# 9. SECURITY ANALYSIS
# ========================================

print("\n[9] SECURITY ANALYSIS")

if success_count == 1 and failure_count == TOTAL_REQUESTS - 1:

    print(
        "[PASS] Exactly one authentication succeeded"
    )

    print(
        "[PASS] All concurrent replays were rejected"
    )

    print(
        "[PASS] No concurrent challenge replay detected"
    )

elif success_count > 1:

    print(
        "[FAIL] RACE CONDITION DETECTED"
    )

    print(
        f"[FAIL] {success_count} concurrent requests were accepted"
    )

elif success_count == 0:

    print(
        "[FAIL] No authentication succeeded"
    )

    print(
        "[FAIL] Test cannot confirm race protection"
    )

else:

    print(
        "[FAIL] Unexpected authentication result"
    )


# ========================================
# 10. CLEANUP
# ========================================

print("\n[10] CLEANUP")

cleanup()

print("[PASS] Test account removed")

print()
print("=" * 70)
print("V0.8.4 CONCURRENT CHALLENGE RACE TEST FINISHED")
print("=" * 70)

