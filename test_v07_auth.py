import os
import requests
import urllib3

from app.client_auth import create_client_signature
from app.database import get_user


BASE_URL = "https://127.0.0.1:8443"
USERNAME = "V03Test"

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


print("=" * 50)
print("       DPAS V0.7 AUTHENTICATION TEST")
print("=" * 50)


# ========================================
# GET USER
# ========================================

user = get_user(
    USERNAME
)

if user is None:
    print("[FAIL] User not found")
    raise SystemExit(1)

auth_salt = user[6]

if auth_salt is None:
    print("[FAIL] Authentication salt missing")
    raise SystemExit(1)

print("[PASS] User loaded")


# ========================================
# STEP 1
# GET CHALLENGE
# ========================================

response = requests.post(
    f"{BASE_URL}/auth/challenge",
    json={
        "username": USERNAME
    },
    verify=False,
    timeout=5
)

if response.status_code != 200:

    print("[FAIL] Challenge request")
    print(response.text)

    raise SystemExit(1)

challenge_data = response.json()

challenge = challenge_data["challenge"]

print("[PASS] Challenge received")
print("Challenge:", challenge)


# ========================================
# STEP 2
# CREATE SIGNATURE
# ========================================

try:

    signature = create_client_signature(
        USERNAME,
        os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!"),
        auth_salt,
        challenge
    )

    print("[PASS] Signature generated")

except Exception as error:

    print("[FAIL] Signature generation")
    print(error)

    raise SystemExit(1)


# ========================================
# STEP 3
# VERIFY SIGNATURE
# ========================================

response = requests.post(
    f"{BASE_URL}/auth/verify",
    json={
        "username": USERNAME,
        "challenge": challenge,
        "signature": signature
    },
    verify=False,
    timeout=5
)

if response.status_code != 200:

    print("[FAIL] Authentication verification")
    print(response.text)

    raise SystemExit(1)

auth_data = response.json()

token = auth_data.get(
    "token"
)

if not token:

    print("[FAIL] Session token missing")
    raise SystemExit(1)

print("[PASS] Authentication accepted")
print("[PASS] Session token received")


# ========================================
# STEP 4
# SESSION
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {token}"
    },
    verify=False,
    timeout=5
)

if response.status_code != 200:

    print("[FAIL] Session validation")
    print(response.text)

    raise SystemExit(1)

session_data = response.json()

if session_data.get("username") != USERNAME:

    print("[FAIL] Wrong session username")
    raise SystemExit(1)

print("[PASS] Session validated")


# ========================================
# STEP 5
# REPLAY ATTACK
# ========================================

response = requests.post(
    f"{BASE_URL}/auth/verify",
    json={
        "username": USERNAME,
        "challenge": challenge,
        "signature": signature
    },
    verify=False,
    timeout=5
)

if response.status_code == 401:

    print("[PASS] Replay attack rejected")

else:

    print("[FAIL] Replay attack accepted")


# ========================================
# STEP 6
# LOGOUT
# ========================================

response = requests.post(
    f"{BASE_URL}/logout",
    headers={
        "Authorization": f"Bearer {token}"
    },
    verify=False,
    timeout=5
)

if response.status_code != 200:

    print("[FAIL] Logout")
    print(response.text)

    raise SystemExit(1)

print("[PASS] Logout successful")


# ========================================
# STEP 7
# SESSION AFTER LOGOUT
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {token}"
    },
    verify=False,
    timeout=5
)

if response.status_code == 401:

    print("[PASS] Revoked session rejected")

else:

    print("[FAIL] Revoked session still accepted")


print()
print("=" * 50)
print("       DPAS V0.7 TEST COMPLETE")
print("=" * 50)
