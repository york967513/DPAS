import requests

from app.auth import register_user
from app.client_storage import save_private_key
from app.database import get_user, get_challenge


BASE = "http://127.0.0.1:8000"

USERNAME = "V082ReplayTest"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

print("=" * 70)
print("DPAS V0.8.2 AUTH CHALLENGE REPLAY TEST")
print("=" * 70)


print("\n[1] CREATE TEST USER")

existing = get_user(USERNAME)

if existing is None:

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
    print("USERNAME:", USERNAME)

else:

    print("[INFO] Test user already exists")

    key_path = (
        "data/client_keys/"
        + USERNAME
        + ".key"
    )

    import os

    if not os.path.exists(key_path):

        registration = register_user(
            USERNAME,
            PASSWORD
        )

        if registration is None:
            print("[FAIL] Existing user has no usable client key")
            raise SystemExit(1)


print("\n[2] CHECK TEST USER")

user = get_user(
    USERNAME
)

if user is None:
    print("[FAIL] Test user does not exist")
    raise SystemExit(1)

print("USERNAME:", user[1])
print("AUTH SALT:", "present" if user[6] else "missing")
print("PUBLIC KEY:", "present" if user[7] else "missing")


print("\n[3] CREATE CHALLENGE")

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
    raise SystemExit(1)

data = response.json()

challenge = data["challenge"]

print("[PASS] Challenge obtained")
print("CHALLENGE LENGTH:", len(challenge))


print("\n[4] CREATE VALID SIGNATURE")

from app.client_auth import create_client_signature

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
    raise SystemExit(1)

print("[PASS] Valid signature created")
print("SIGNATURE LENGTH:", len(signature))


print("\n[5] FIRST VERIFY")

response1 = requests.post(
    f"{BASE}/auth/verify",
    json={
        "username": USERNAME,
        "challenge": challenge,
        "signature": signature
    }
)

print("STATUS:", response1.status_code)
print("BODY:", response1.text)


print("\n[6] CHECK CHALLENGE STATE AFTER FIRST VERIFY")

challenge_row = get_challenge(
    USERNAME,
    challenge
)

if challenge_row is None:

    print("[FAIL] Challenge disappeared")
    raise SystemExit(1)

print("CHALLENGE USED:", challenge_row[4])

if challenge_row[4] == 1:
    print("[PASS] Challenge marked as used")
else:
    print("[FAIL] Challenge was not marked as used")


print("\n[7] REPLAY SAME CHALLENGE + SAME SIGNATURE")

response2 = requests.post(
    f"{BASE}/auth/verify",
    json={
        "username": USERNAME,
        "challenge": challenge,
        "signature": signature
    }
)

print("STATUS:", response2.status_code)
print("BODY:", response2.text)


print("\n[8] ANALYSIS")

if response1.status_code == 200 and response2.status_code == 401:

    print("[PASS] Challenge replay rejected")
    print("First authentication succeeded.")
    print("Second authentication using the identical challenge/signature was rejected.")

else:

    print("[FAIL] Unexpected replay behaviour")

    print(
        "FIRST STATUS:",
        response1.status_code
    )

    print(
        "REPLAY STATUS:",
        response2.status_code
    )


print("\n[9] CLEANUP")

from app.database import reset_failed_attempts

reset_failed_attempts(
    USERNAME
)

print("[PASS] Account state reset")


print()
print("=" * 70)
print("V0.8.2 REPLAY TEST FINISHED")
print("=" * 70)

