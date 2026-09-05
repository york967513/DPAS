import os
from app.dpas_client import DPASClient
from app.database import get_user


BASE_URL = "https://127.0.0.1:8443"
USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    raise SystemExit(1)

SALT = user[6]

if SALT is None:
    print("[FAIL] Authentication salt missing")
    raise SystemExit(1)


print("=" * 50)
print("       DPAS CLIENT V0.7 TEST")
print("=" * 50)


# ========================================
# CREATE CLIENT
# ========================================

client = DPASClient(
    BASE_URL,
    USERNAME,
    PASSWORD,
    SALT,
    verify_tls=False
)

print("[PASS] Client created")


# ========================================
# INITIAL STATE
# ========================================

if not client.is_authenticated():

    print("[PASS] Initial state: not authenticated")

else:

    print("[FAIL] Client authenticated unexpectedly")
    raise SystemExit(1)


# ========================================
# AUTHENTICATE
# ========================================

if client.authenticate():

    print("[PASS] Authentication successful")

else:

    print("[FAIL] Authentication failed")
    raise SystemExit(1)


# ========================================
# SESSION STATE
# ========================================

if client.is_authenticated():

    print("[PASS] Client authenticated")

else:

    print("[FAIL] Client authentication state invalid")
    raise SystemExit(1)


# ========================================
# SESSION ENDPOINT
# ========================================

response = client.session()

if response.status_code != 200:

    print("[FAIL] Session endpoint")
    print(response.text)
    raise SystemExit(1)

session_data = response.json()

if session_data.get("username") != USERNAME:

    print("[FAIL] Wrong username in session")
    raise SystemExit(1)

print("[PASS] Session endpoint")


# ========================================
# TOKEN EXISTS
# ========================================

if client.session_token:

    print("[PASS] Session token stored")

else:

    print("[FAIL] Session token missing")
    raise SystemExit(1)


# ========================================
# LOGOUT
# ========================================

if client.logout():

    print("[PASS] Logout successful")

else:

    print("[FAIL] Logout failed")
    raise SystemExit(1)


# ========================================
# STATE AFTER LOGOUT
# ========================================

if not client.is_authenticated():

    print("[PASS] Client unauthenticated after logout")

else:

    print("[FAIL] Client still authenticated")
    raise SystemExit(1)


# ========================================
# REVOKED TOKEN
# ========================================

if client.session_token is None:

    print("[PASS] Local session token cleared")

else:

    print("[FAIL] Local session token still exists")
    raise SystemExit(1)


print()
print("=" * 50)
print("       DPAS CLIENT TEST PASSED")
print("=" * 50)
