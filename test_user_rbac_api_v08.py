import os
import requests

from app.dpas_client import DPASClient
from app.database import get_user


BASE_URL = "https://127.0.0.1:8443"
VERIFY_TLS = False
USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

print("=" * 55)
print("       DPAS V0.8 USER RBAC API TEST")
print("=" * 55)

user = get_user(USERNAME)

if user is None:
    print("[FAIL] Test user not found")
    raise SystemExit(1)

print("[PASS] User loaded")

client = DPASClient(
    BASE_URL,
    USERNAME,
    PASSWORD,
    user[6],
    VERIFY_TLS
)

print("[PASS] Client created")

if not client.authenticate():
    print("[FAIL] Authentication")
    raise SystemExit(1)

print("[PASS] Authentication")

response = requests.get(
    f"{BASE_URL}/protected/profile/read",
    headers=client.authorization_header(),
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

response = requests.put(
    f"{BASE_URL}/protected/profile/write",
    json={
        "display_name": "V03Test"
    },
    headers=client.authorization_header(),
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

response = requests.get(
    f"{BASE_URL}/admin/users",
    headers=client.authorization_header(),
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

response = requests.delete(
    f"{BASE_URL}/admin/users/V02Test",
    headers=client.authorization_header(),
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

if client.logout():
    print("[PASS] Logout")
else:
    print("[FAIL] Logout")
    raise SystemExit(1)

print()
print("=" * 55)
print("       DPAS V0.8 USER RBAC API TEST PASSED")
print("=" * 55)


