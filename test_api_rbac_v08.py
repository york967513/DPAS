import os
import requests
import urllib3

from app.dpas_client import DPASClient
from app.database import get_user


BASE_URL = "https://127.0.0.1:8443"
USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


print("=" * 55)
print("       DPAS V0.8 API RBAC TEST")
print("=" * 55)


# ========================================
# LOAD USER
# ========================================

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    raise SystemExit(1)

salt = user[6]

print("[PASS] User loaded")


# ========================================
# CREATE CLIENT
# ========================================

client = DPASClient(
    BASE_URL,
    USERNAME,
    PASSWORD,
    salt,
    verify_tls=False
)

print("[PASS] Client created")


# ========================================
# AUTHENTICATE
# ========================================

if not client.authenticate():
    print("[FAIL] Authentication")
    raise SystemExit(1)

print("[PASS] Authentication")


headers = client.authorization_header()


# ========================================
# profile.read
# ========================================

response = requests.get(
    f"{BASE_URL}/protected/profile/read",
    headers=headers,
    verify=False,
    timeout=5
)

if response.status_code == 200:

    print("[PASS] profile.read allowed")

else:

    print("[FAIL] profile.read denied")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ========================================
# users.delete
# ========================================

response = requests.delete(
    f"{BASE_URL}/protected/users",
    headers=headers,
    verify=False,
    timeout=5
)

if response.status_code == 403:

    print("[PASS] users.delete denied")

else:

    print("[FAIL] users.delete security failure")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ========================================
# MISSING TOKEN
# ========================================

response = requests.get(
    f"{BASE_URL}/protected/profile/read",
    verify=False,
    timeout=5
)

if response.status_code == 401:

    print("[PASS] Missing token rejected")

else:

    print("[FAIL] Missing token accepted")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)

# ========================================
# LOGOUT
# ========================================

logout_success = client.logout()

if logout_success:

    print("[PASS] Logout")

else:

    print("[FAIL] Logout")
    raise SystemExit(1)

# ========================================
# REVOKED SESSION
# ========================================

if not client.is_authenticated():

    print("[PASS] Client unauthenticated after logout")

else:

    print("[FAIL] Client still authenticated")
    raise SystemExit(1)


print()
print("=" * 55)
print("       DPAS V0.8 API RBAC TEST PASSED")
print("=" * 55)

