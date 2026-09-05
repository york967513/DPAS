import os
import requests

BASE_URL = "http://127.0.0.1:8000"

NORMAL_USER = "V07Normal3"
NORMAL_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

ADMIN_USER = "V07Admin3"
ADMIN_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

print("=" * 70)
print("DPAS V0.7 AUTHORIZATION / RBAC API ABUSE TEST")
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
        response.status_code,
        response.text
    )

    if response.status_code != 200:
        return None

    return response.json().get("token")


def request(
    method,
    path,
    token,
    expected_status,
    **kwargs
):

    response = requests.request(
        method,
        f"{BASE_URL}{path}",
        headers={
            "Authorization": f"Bearer {token}"
        },
        **kwargs
    )

    passed = (
        response.status_code
        == expected_status
    )

    print(
        f"{method} {path}:",
        response.status_code,
        "EXPECTED:",
        expected_status
    )

    print(
        "BODY:",
        response.text
    )

    print(
        "[PASS]" if passed else "[FAIL]",
        path
    )

    return passed


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
    print("[FAIL] Normal user authentication")
    raise SystemExit(1)

print("[PASS] Normal user authenticated")
print("NORMAL TOKEN LENGTH:", len(normal_token))

if admin_token is None:
    print("[FAIL] Admin authentication")
    raise SystemExit(1)

print("[PASS] Admin authenticated")
print("ADMIN TOKEN LENGTH:", len(admin_token))


# ============================================================
# 2. NORMAL USER — ALLOWED PERMISSION
# ============================================================

print()
print("[2] NORMAL USER — ALLOWED ACCESS")

request(
    "GET",
    "/protected/profile/read",
    normal_token,
    200
)


# ============================================================
# 3. NORMAL USER — VERTICAL PRIVILEGE ESCALATION
# ============================================================

print()
print("[3] NORMAL USER — PRIVILEGE ESCALATION")

request(
    "PUT",
    "/protected/profile/write",
    normal_token,
    403,
    json={
        "display_name": "Unauthorized"
    }
)

request(
    "GET",
    "/admin/users",
    normal_token,
    403
)

request(
    "DELETE",
    "/protected/users",
    normal_token,
    403
)


# ============================================================
# 4. ADMIN USER — AUTHORIZED ACCESS
# ============================================================

print()
print("[4] ADMIN USER — AUTHORIZED ACCESS")

request(
    "GET",
    "/protected/profile/read",
    admin_token,
    200
)

request(
    "PUT",
    "/protected/profile/write",
    admin_token,
    200,
    json={
        "display_name": "V07AdminTest"
    }
)

request(
    "GET",
    "/admin/users",
    admin_token,
    200
)

request(
    "DELETE",
    "/protected/users",
    admin_token,
    200
)


# ============================================================
# 5. TOKEN BOUNDARY
# ============================================================

print()
print("[5] TOKEN BOUNDARY")

modified_token = (
    normal_token[:-1]
    + (
        "A"
        if normal_token[-1] != "A"
        else "B"
    )
)

request(
    "GET",
    "/session",
    modified_token,
    401
)

request(
    "GET",
    "/session",
    "invalid-random-token",
    401
)


# ============================================================
# 6. MISSING AUTHORIZATION
# ============================================================

print()
print("[6] MISSING AUTHORIZATION")

response = requests.get(
    f"{BASE_URL}/admin/users"
)

print(
    "STATUS:",
    response.status_code
)

print(
    "BODY:",
    response.text
)

if response.status_code == 401:
    print(
        "[PASS] Missing Authorization rejected"
    )
else:
    print(
        "[FAIL] Missing Authorization accepted"
    )


# ============================================================
# 7. SESSION IDENTITY
# ============================================================

print()
print("[7] SESSION IDENTITY")

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization":
            f"Bearer {normal_token}"
    }
)

print(
    "NORMAL SESSION:",
    response.status_code,
    response.text
)

if (
    response.status_code == 200
    and response.json().get("username")
    == NORMAL_USER
):
    print(
        "[PASS] Normal token resolves to normal user"
    )
else:
    print(
        "[FAIL] Normal token identity mismatch"
    )


response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization":
            f"Bearer {admin_token}"
    }
)

print(
    "ADMIN SESSION:",
    response.status_code,
    response.text
)

if (
    response.status_code == 200
    and response.json().get("username")
    == ADMIN_USER
):
    print(
        "[PASS] Admin token resolves to admin user"
    )
else:
    print(
        "[FAIL] Admin token identity mismatch"
    )


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 70)
print("V0.7 AUTHORIZATION / RBAC API ABUSE TEST FINISHED")
print("=" * 70)

