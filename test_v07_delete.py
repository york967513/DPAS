import os
import requests

BASE_URL = "http://127.0.0.1:8000"

NORMAL_USER = "V07Normal3"
NORMAL_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

ADMIN_USER = "V07Admin3"
ADMIN_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

TARGET_USER = "V07DeleteTarget"

print("=" * 70)
print("DPAS V0.7 DESTRUCTIVE RBAC / USER DELETE TEST")
print("=" * 70)


def login(username, password):

    response = requests.post(
        f"{BASE_URL}/login",
        json={
            "username": username,
            "password": password
        }
    )

    print(
        f"LOGIN {username}:",
        response.status_code
    )

    if response.status_code != 200:
        print("BODY:", response.text)
        return None

    return response.json()["token"]


def delete_user(username, token):

    response = requests.delete(
        f"{BASE_URL}/admin/users/{username}",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    print(
        f"DELETE {username}:",
        response.status_code
    )

    print(
        "BODY:",
        response.text
    )

    return response


# ============================================================
# 1. AUTHENTICATION
# ============================================================

print()
print("[1] AUTHENTICATION")

normal_token = login(
    NORMAL_USER,
    NORMAL_PASSWORD
)

admin_token = login(
    ADMIN_USER,
    ADMIN_PASSWORD
)

if normal_token is None:
    print("[FAIL] Normal authentication")
    raise SystemExit(1)

print("[PASS] Normal user authenticated")

if admin_token is None:
    print("[FAIL] Admin authentication")
    raise SystemExit(1)

print("[PASS] Admin authenticated")


# ============================================================
# 2. NORMAL USER DELETE ATTEMPT
# ============================================================

print()
print("[2] NORMAL USER DELETE ATTEMPT")

response = delete_user(
    TARGET_USER,
    normal_token
)

if response.status_code == 403:

    print(
        "[PASS] Normal user cannot delete another user"
    )

else:

    print(
        "[FAIL] Normal user DELETE authorization bypass"
    )


# ============================================================
# 3. VERIFY TARGET STILL EXISTS
# ============================================================

print()
print("[3] VERIFY TARGET STILL EXISTS")

response = requests.get(
    f"{BASE_URL}/admin/users",
    headers={
        "Authorization":
            f"Bearer {admin_token}"
    }
)

if response.status_code != 200:

    print(
        "[FAIL] Cannot query users as admin"
    )

    raise SystemExit(1)

users = response.json()["users"]

target_exists = any(
    user["username"] == TARGET_USER
    for user in users
)

if target_exists:

    print(
        "[PASS] Delete target still exists"
    )

else:

    print(
        "[FAIL] Target disappeared after unauthorized request"
    )

    raise SystemExit(1)


# ============================================================
# 4. ADMIN DELETE
# ============================================================

print()
print("[4] ADMIN DELETE")

response = delete_user(
    TARGET_USER,
    admin_token
)

if response.status_code == 200:

    print(
        "[PASS] Admin successfully deleted target"
    )

else:

    print(
        "[FAIL] Admin could not delete target"
    )

    raise SystemExit(1)


# ============================================================
# 5. VERIFY TARGET WAS ACTUALLY DELETED
# ============================================================

print()
print("[5] VERIFY TARGET DELETED")

response = requests.get(
    f"{BASE_URL}/admin/users",
    headers={
        "Authorization":
            f"Bearer {admin_token}"
    }
)

if response.status_code != 200:

    print(
        "[FAIL] Cannot query users after deletion"
    )

    raise SystemExit(1)

users = response.json()["users"]

target_exists = any(
    user["username"] == TARGET_USER
    for user in users
)

if not target_exists:

    print(
        "[PASS] Target user removed from database"
    )

else:

    print(
        "[FAIL] Target user still exists"
    )


# ============================================================
# 6. DELETE NON-EXISTENT USER
# ============================================================

print()
print("[6] DELETE NON-EXISTENT USER")

response = delete_user(
    TARGET_USER,
    admin_token
)

if response.status_code == 404:

    print(
        "[PASS] Non-existent user correctly returns 404"
    )

else:

    print(
        "[FAIL] Unexpected response for non-existent user"
    )


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 70)
print("V0.7 DESTRUCTIVE RBAC / USER DELETE TEST FINISHED")
print("=" * 70)

