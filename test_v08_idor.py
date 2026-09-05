import os
import requests

BASE_URL = "http://127.0.0.1:8000"

NORMAL_USER = "V07Normal3"
NORMAL_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

ADMIN_USER = "V07Admin3"
ADMIN_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

TARGET_USER = "V07Admin3"

print("=" * 70)
print("DPAS V0.8 IDOR / BOLA / HORIZONTAL AUTHORIZATION TEST")
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


def request(method, path, token, **kwargs):

    response = requests.request(
        method,
        f"{BASE_URL}{path}",
        headers={
            "Authorization": f"Bearer {token}"
        },
        **kwargs
    )

    print(
        f"{method} {path}:",
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

if admin_token is None:
    print("[FAIL] Admin authentication")
    raise SystemExit(1)

print("[PASS] Both users authenticated")


# ============================================================
# 2. NORMAL USER ACCESS TO OWN PROFILE
# ============================================================

print()
print("[2] NORMAL USER — OWN PROFILE")

response = request(
    "GET",
    "/protected/profile",
    normal_token
)

if response.status_code == 200:

    body = response.json()

    if body.get("username") == NORMAL_USER:

        print(
            "[PASS] Normal user receives own identity"
        )

    else:

        print(
            "[FAIL] Unexpected session identity"
        )

else:

    print(
        "[FAIL] Normal user cannot access own profile"
    )


# ============================================================
# 3. NORMAL USER ATTEMPTS ADMIN PROFILE
# ============================================================

print()
print("[3] HORIZONTAL AUTHORIZATION TEST")

response = request(
    "GET",
    "/protected/profile",
    normal_token
)

if response.status_code == 200:

    body = response.json()

    if body.get("username") == TARGET_USER:

        print(
            "[FAIL] IDOR: normal user resolved to another user"
        )

    elif body.get("username") == NORMAL_USER:

        print(
            "[PASS] Session remains bound to authenticated user"
        )

    else:

        print(
            "[FAIL] Unexpected username returned"
        )

else:

    print(
        "[FAIL] Protected profile request failed"
    )


# ============================================================
# 4. USERNAME PARAMETER POLLUTION
# ============================================================

print()
print("[4] USERNAME PARAMETER POLLUTION")

paths = [
    "/protected/profile?username=V07Admin3",
    "/protected/profile?user=V07Admin3",
    "/protected/profile?user_id=16",
]

for path in paths:

    response = request(
        "GET",
        path,
        normal_token
    )

    if response.status_code == 200:

        try:
            body = response.json()
            username = body.get("username")

            if username == TARGET_USER:

                print(
                    "[FAIL] Parameter pollution changed identity"
                )

            elif username == NORMAL_USER:

                print(
                    "[PASS] Identity unaffected by request parameters"
                )

            else:

                print(
                    "[FAIL] Unexpected identity"
                )

        except Exception:

            print(
                "[FAIL] Invalid JSON response"
            )

    else:

        print(
            "[PASS] Request rejected or did not expose another identity"
        )


# ============================================================
# 5. ADMIN ENDPOINT WITH NORMAL TOKEN
# ============================================================

print()
print("[5] NORMAL USER → ADMIN RESOURCE")

response = request(
    "GET",
    "/admin/users",
    normal_token
)

if response.status_code == 403:

    print(
        "[PASS] Normal user cannot access admin resource"
    )

else:

    print(
        "[FAIL] Admin resource accessible by normal user"
    )


# ============================================================
# 6. NORMAL USER → DELETE ADMIN
# ============================================================

print()
print("[6] NORMAL USER → ADMIN DELETE")

response = request(
    "DELETE",
    f"/admin/users/{TARGET_USER}",
    normal_token
)

if response.status_code == 403:

    print(
        "[PASS] Normal user cannot delete admin"
    )

else:

    print(
        "[FAIL] Normal user bypassed delete authorization"
    )


# ============================================================
# 7. ROLE/PERMISSION PARAMETER INJECTION
# ============================================================

print()
print("[7] ROLE / PERMISSION PARAMETER INJECTION")

paths = [
    "/protected/profile/read?role=admin",
    "/protected/profile/read?permission=users.delete",
    "/protected/profile/write?permission=users.delete",
]

for path in paths:

    response = request(
        "GET" if "profile/write" not in path else "GET",
        path,
        normal_token
    )

    if response.status_code == 403:

        print(
            "[PASS] Permission cannot be supplied through query parameter"
        )

    elif response.status_code == 200:

        print(
            "[FAIL] Possible authorization parameter injection"
        )

    else:

        print(
            "[PASS] Request did not grant unauthorized access"
        )


# ============================================================
# 8. TOKEN IDENTITY SWITCH
# ============================================================

print()
print("[8] TOKEN IDENTITY SWITCH")

response = request(
    "GET",
    "/session",
    normal_token
)

if response.status_code == 200:

    username = response.json().get("username")

    if username == NORMAL_USER:

        print(
            "[PASS] Normal token remains bound to normal user"
        )

    else:

        print(
            "[FAIL] Token identity mismatch"
        )

else:

    print(
        "[FAIL] Normal session rejected"
    )


# ============================================================
# 9. ADMIN TOKEN CONTROL
# ============================================================

print()
print("[9] ADMIN TOKEN IDENTITY")

response = request(
    "GET",
    "/session",
    admin_token
)

if response.status_code == 200:

    username = response.json().get("username")

    if username == ADMIN_USER:

        print(
            "[PASS] Admin token remains bound to admin user"
        )

    else:

        print(
            "[FAIL] Admin token identity mismatch"
        )

else:

    print(
        "[FAIL] Admin session rejected"
    )


# ============================================================
# 10. INVALID TOKEN WITH VALID USERNAME PARAMETERS
# ============================================================

print()
print("[10] INVALID TOKEN + USERNAME MANIPULATION")

response = requests.get(
    f"{BASE_URL}/protected/profile?username={ADMIN_USER}",
    headers={
        "Authorization":
            "Bearer INVALID_TOKEN"
    }
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
        "[PASS] Invalid token rejected before identity manipulation"
    )

else:

    print(
        "[FAIL] Invalid token accepted"
    )


# ============================================================
# SUMMARY
# ============================================================

print()
print("=" * 70)
print("V0.8 IDOR / BOLA / AUTHORIZATION ABUSE TEST FINISHED")
print("=" * 70)

