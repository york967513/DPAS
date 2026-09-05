import os
import requests

from app.dpas_client import DPASClient
from app.database import get_user

BASE_URL = "https://127.0.0.1:8443"
VERIFY_TLS = False

USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

print("=" * 55)
print("       DPAS V0.8 AUTH/SESSION REGRESSION TEST")
print("=" * 55)

user = get_user(USERNAME)

if user is None:
    print("[FAIL] Test user not found")
    raise SystemExit(1)

print("[PASS] Test user loaded")


# ==========================================
# CORRECT AUTHENTICATION
# ==========================================

client = DPASClient(
    BASE_URL,
    USERNAME,
    PASSWORD,
    user[6],
    VERIFY_TLS
)

if not client.authenticate():
    print("[FAIL] Correct authentication rejected")
    raise SystemExit(1)

print("[PASS] Correct authentication")


# ==========================================
# SESSION
# ==========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers=client.authorization_header(),
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 200:
    print("[PASS] Valid session accepted")
else:
    print("[FAIL] Valid session rejected")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# MISSING TOKEN
# ==========================================

response = requests.get(
    f"{BASE_URL}/session",
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 401:
    print("[PASS] Missing token rejected")
else:
    print("[FAIL] Missing token accepted")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# INVALID TOKEN
# ==========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": "Bearer invalid-token"
    },
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 401:
    print("[PASS] Invalid token rejected")
else:
    print("[FAIL] Invalid token accepted")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# WRONG PASSWORD
# ==========================================

bad_client = DPASClient(
    BASE_URL,
    USERNAME,
    "WRONG_PASSWORD_2026!",
    user[6],
    VERIFY_TLS
)

if not bad_client.authenticate():
    print("[PASS] Wrong password rejected")
else:
    print("[FAIL] Wrong password accepted")
    raise SystemExit(1)


# ==========================================
# SAVE TOKEN BEFORE LOGOUT
# ==========================================

old_authorization = client.authorization_header()


# ==========================================
# LOGOUT
# ==========================================

if client.logout():
    print("[PASS] Logout")
else:
    print("[FAIL] Logout failed")
    raise SystemExit(1)


# ==========================================
# TOKEN AFTER LOGOUT
# ==========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers=old_authorization,
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 401:
    print("[PASS] Token rejected after logout")
else:
    print("[FAIL] Token still valid after logout")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


print()
print("=" * 55)
print("       DPAS V0.8 AUTH/SESSION TEST PASSED")
print("=" * 55)

