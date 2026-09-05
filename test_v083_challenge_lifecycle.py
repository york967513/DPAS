import os
import requests
import sqlite3
import time

BASE = "http://127.0.0.1:8000"
USERNAME = "V083ChallengeTest"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

DB = "data/dpas.db"


def db_state():
    connection = sqlite3.connect(DB)
    cursor = connection.cursor()

    row = cursor.execute("""
        SELECT failed_attempts, locked_until
        FROM users
        WHERE username = ?
    """, (USERNAME,)).fetchone()

    challenges = cursor.execute("""
        SELECT challenge, created_at, used
        FROM challenges
        WHERE username = ?
        ORDER BY id
    """, (USERNAME,)).fetchall()

    connection.close()

    return row, challenges


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


print("=" * 70)
print("DPAS V0.8.3 CHALLENGE LIFECYCLE / STALE CHALLENGE TEST")
print("=" * 70)


print("\n[1] CREATE TEST USER")

cleanup()

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


print("\n[2] CREATE CHALLENGE A")

r1 = requests.post(
    f"{BASE}/auth/challenge",
    json={
        "username": USERNAME
    }
)

print("STATUS:", r1.status_code)
print("BODY:", r1.text)

if r1.status_code != 200:
    print("[FAIL] Challenge A creation failed")
    cleanup()
    raise SystemExit(1)

challenge_a = r1.json()["challenge"]

print("[PASS] Challenge A obtained")
print("CHALLENGE A:", challenge_a)


print("\n[3] CREATE CHALLENGE B")

r2 = requests.post(
    f"{BASE}/auth/challenge",
    json={
        "username": USERNAME
    }
)

print("STATUS:", r2.status_code)
print("BODY:", r2.text)

if r2.status_code != 200:
    print("[FAIL] Challenge B creation failed")
    cleanup()
    raise SystemExit(1)

challenge_b = r2.json()["challenge"]

print("[PASS] Challenge B obtained")
print("CHALLENGE B:", challenge_b)


print("\n[4] CHECK CHALLENGE STORAGE")

state, challenges = db_state()

print("USER STATE:", state)

for index, row in enumerate(challenges, 1):
    print(
        f"CHALLENGE {index}:",
        "VALUE=", row[0],
        "| CREATED=", row[1],
        "| USED=", row[2]
    )

if challenge_a == challenge_b:
    print("[FAIL] Challenge values are identical")
else:
    print("[PASS] Challenges are unique")


print("\n[5] VERIFY CHALLENGE LIFECYCLE")

connection = sqlite3.connect(DB)
cursor = connection.cursor()

row_a = cursor.execute("""
    SELECT used
    FROM challenges
    WHERE username = ?
      AND challenge = ?
""", (
    USERNAME,
    challenge_a
)).fetchone()

row_b = cursor.execute("""
    SELECT used
    FROM challenges
    WHERE username = ?
      AND challenge = ?
""", (
    USERNAME,
    challenge_b
)).fetchone()

connection.close()

print("CHALLENGE A STATE:", row_a)
print("CHALLENGE B STATE:", row_b)

if row_a is None and row_b is not None and row_b[0] == 0:
    print("[PASS] Only the newest challenge remains active")
else:
    print("[FAIL] Challenge lifecycle/storage policy violated")


print("\n[6] CREATE VALID SIGNATURE FOR CHALLENGE A")

from app.database import get_user
from app.client_auth import create_client_signature

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    cleanup()
    raise SystemExit(1)

auth_salt = user[6]

try:

    signature_a = create_client_signature(
        USERNAME,
        PASSWORD,
        auth_salt,
        challenge_a
    )

except Exception as e:

    print("[FAIL] Could not create signature for Challenge A")
    print(type(e).__name__, str(e))
    cleanup()
    raise SystemExit(1)

print("[PASS] Signature A created")


print("\n[7] VERIFY OLD CHALLENGE A AFTER CHALLENGE B EXISTS")

r3 = requests.post(
    f"{BASE}/auth/verify",
    json={
        "username": USERNAME,
        "challenge": challenge_a,
        "signature": signature_a
    }
)

print("STATUS:", r3.status_code)
print("BODY:", r3.text)


print("\n[8] CHECK CHALLENGE A STATE")

connection = sqlite3.connect(DB)
cursor = connection.cursor()

row_a_after = cursor.execute("""
    SELECT used
    FROM challenges
    WHERE username = ?
      AND challenge = ?
""", (
    USERNAME,
    challenge_a
)).fetchone()

connection.close()

print("CHALLENGE A AFTER VERIFY:", row_a_after)


print("\n[9] ANALYSIS")

if r3.status_code == 401:

    print("[PASS] Old Challenge A was rejected")

elif r3.status_code == 200:

    print("[FAIL] Invalidated Challenge A was accepted")

else:

    print("[FAIL] Unexpected HTTP response:", r3.status_code)


print("\n[10] CHECK CHALLENGE B")

connection = sqlite3.connect(DB)
cursor = connection.cursor()

row_b_after = cursor.execute("""
    SELECT used
    FROM challenges
    WHERE username = ?
      AND challenge = ?
""", (
    USERNAME,
    challenge_b
)).fetchone()

connection.close()

print("CHALLENGE B STATE:", row_b_after)

if row_b_after is not None:
    print("[PASS] Challenge B still exists")
else:
    print("[FAIL] Challenge B disappeared unexpectedly")


print("\n[11] CLEANUP")

cleanup()

print("[PASS] Test data removed")

print()
print("=" * 70)
print("V0.8.3 CHALLENGE LIFECYCLE TEST FINISHED")
print("=" * 70)

