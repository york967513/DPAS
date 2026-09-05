import os
import requests

from app.dpas_client import DPASClient
from app.database import get_user


BASE_URL = "https://127.0.0.1:8443"
VERIFY_TLS = False

USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

print("=" * 55)
print("       DPAS V0.8 RBAC SECURITY REGRESSION")
print("=" * 55)


# ==========================================
# CHECK USER
# ==========================================

user = get_user(USERNAME)

if user is None:
    print("[FAIL] Test user not found")
    raise SystemExit(1)

print("[PASS] Test user loaded")


# ==========================================
# CREATE CLIENT
# ==========================================

client = DPASClient(
    BASE_URL,
    USERNAME,
    PASSWORD,
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


headers = client.authorization_header()


# ==========================================
# PROFILE READ
# ==========================================

response = requests.get(
    f"{BASE_URL}/protected/profile/read",
    headers=headers,
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 200:
    print("[PASS] profile.read allowed")
else:
    print("[FAIL] profile.read denied")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# PROFILE WRITE
# ==========================================

response = requests.put(
    f"{BASE_URL}/protected/profile/write",
    json={
        "display_name": "V03Test"
    },
    headers=headers,
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 200:
    print("[PASS] profile.write allowed")
else:
    print("[FAIL] profile.write denied")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# ADMIN LIST USERS
# ==========================================

response = requests.get(
    f"{BASE_URL}/admin/users",
    headers=headers,
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 403:
    print("[PASS] users.read denied")
else:
    print("[FAIL] users.read unexpected response")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# ADMIN DELETE USER
# ==========================================

response = requests.delete(
    f"{BASE_URL}/admin/users/V02Test",
    headers=headers,
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 403:
    print("[PASS] users.delete denied")
else:
    print("[FAIL] users.delete unexpected response")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# ADMIN LIST WITHOUT TOKEN
# ==========================================

response = requests.get(
    f"{BASE_URL}/admin/users",
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 401:
    print("[PASS] Admin endpoint rejects missing token")
else:
    print("[FAIL] Missing token accepted")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


# ==========================================
# ADMIN DELETE WITHOUT TOKEN
# ==========================================

response = requests.delete(
    f"{BASE_URL}/admin/users/V02Test",
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 401:
    print("[PASS] Admin delete rejects missing token")
else:
    print("[FAIL] Admin delete accepted without token")
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


# ==========================================
# OLD TOKEN AFTER LOGOUT
# ==========================================

response = requests.get(
    f"{BASE_URL}/admin/users",
    headers=headers,
    verify=VERIFY_TLS,
    timeout=5
)

if response.status_code == 401:
    print("[PASS] Old token rejected after logout")
else:
    print("[FAIL] Old token still accepted after logout")
    print("Status:", response.status_code)
    print("Response:", response.text)
    raise SystemExit(1)


print()
print("=" * 55)
print("       DPAS V0.8 RBAC SECURITY TEST PASSED")
print("=" * 55)

