import os
import requests

from app.dpas_client import DPASClient
from app.database import get_user


BASE_URL = "https://127.0.0.1:8443"
VERIFY_TLS = False

ADMIN_USERNAME = "V03Test"
ADMIN_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

TARGET_USER = "TestUser"


print("=" * 55)
print("       DPAS V0.8 USER MANAGEMENT TEST")
print("=" * 55)


# ==========================================
# CHECK ADMIN USER
# ==========================================

user = get_user(ADMIN_USERNAME)

if user is None:
    print("[FAIL] Admin user not found")
    raise SystemExit(1)

if user[6] is None:
    print("[FAIL] Admin user has no authentication salt")
    raise SystemExit(1)

if user[7] is None:
    print("[FAIL] Admin user has no public key")
    raise SystemExit(1)

print("[PASS] Admin user loaded")


# ==========================================
# CREATE CLIENT
# ==========================================

client = DPASClient(
    BASE_URL,
    ADMIN_USERNAME,
    ADMIN_PASSWORD,
    user[6],
    VERIFY_TLS
)

print("[PASS] Client created")


# ==========================================
# AUTHENTICATION
# ==========================================

if not client.authenticate():
    print("[FAIL] Authentication")
    raise SystemExit(1)

print("[PASS] Authentication")


# ==========================================
# GET USERS
# ==========================================

response = requests.get(
    f"{BASE_URL}/admin/users",
    headers=client.authorization_header(),
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 200:
    print("[PASS] Admin can list users")
else:
    print("[FAIL] Admin cannot list users")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# CHECK TARGET USER
# ==========================================

if get_user(TARGET_USER) is None:
    print("[FAIL] Target user does not exist:", TARGET_USER)
    raise SystemExit(1)

print("[PASS] Target user exists")


# ==========================================
# DELETE USER
# ==========================================

response = requests.delete(
    f"{BASE_URL}/admin/users/{TARGET_USER}",
    headers=client.authorization_header(),
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 200:
    print("[PASS] Admin can delete user")
else:
    print("[FAIL] User deletion failed")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# VERIFY DELETION
# ==========================================

if get_user(TARGET_USER) is None:
    print("[PASS] User removed from database")
else:
    print("[FAIL] User still exists in database")
    raise SystemExit(1)


# ==========================================
# DELETE NON-EXISTENT USER
# ==========================================

response = requests.delete(
    f"{BASE_URL}/admin/users/{TARGET_USER}",
    headers=client.authorization_header(),
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 404:
    print("[PASS] Non-existent user rejected")
else:
    print("[FAIL] Unexpected response for non-existent user")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# LOGOUT
# ==========================================

if client.logout():
    print("[PASS] Logout")
else:
    print("[FAIL] Logout")
    raise SystemExit(1)


print()
print("=" * 55)
print("       DPAS V0.8 USER MANAGEMENT TEST PASSED")
print("=" * 55)

