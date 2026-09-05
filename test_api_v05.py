import os
import requests


BASE_URL = "http://127.0.0.1:8000"

USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

passed = 0
failed = 0


def test(name, result):
    global passed
    global failed

    if result:
        print(f"[PASS] {name}")
        passed += 1
    else:
        print(f"[FAIL] {name}")
        failed += 1


print("========================================")
print("        DPAS V0.5 API SECURITY TEST")
print("========================================")


# ========================================
# 01. HEALTH
# ========================================

try:

    response = requests.get(
        f"{BASE_URL}/health"
    )

    test(
        "Health endpoint",
        response.status_code == 200
    )

except Exception as error:

    print("[ERROR] Server unavailable")
    print(error)
    raise SystemExit(1)


# ========================================
# 02. CORRECT LOGIN
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": USERNAME,
        "password": PASSWORD
    }
)

test(
    "Correct login",
    response.status_code == 200
)


token = None

if response.status_code == 200:

    data = response.json()

    token = data.get("token")


test(
    "Login returns session token",
    token is not None
)


# ========================================
# 03. SESSION
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {token}"
    }
)

test(
    "Valid session accepted",
    response.status_code == 200
)


# ========================================
# 04. SESSION USER
# ========================================

if response.status_code == 200:

    data = response.json()

    session_username = (
        data.get("username")
    )

else:

    session_username = None


test(
    "Correct username returned",
    session_username == USERNAME
)


# ========================================
# 05. WRONG PASSWORD
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": USERNAME,
        "password": os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")
    }
)

test(
    "Wrong password rejected",
    response.status_code == 401
)


# ========================================
# 06. UNKNOWN USER
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": "UnknownDPASUser",
        "password": PASSWORD
    }
)

test(
    "Unknown user rejected",
    response.status_code == 401
)


# ========================================
# 07. INVALID TOKEN
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": "Bearer INVALID_TOKEN"
    }
)

test(
    "Invalid token rejected",
    response.status_code == 401
)


# ========================================
# 08. MISSING AUTHORIZATION
# ========================================

response = requests.get(
    f"{BASE_URL}/session"
)

test(
    "Missing authorization rejected",
    response.status_code == 401
)


# ========================================
# 09. INVALID AUTHORIZATION FORMAT
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": token
    }
)

test(
    "Invalid authorization format rejected",
    response.status_code == 401
)


# ========================================
# 10. MODIFIED TOKEN
# ========================================

modified_token = (
    token[:-1] + "A"
)

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {modified_token}"
    }
)

test(
    "Modified token rejected",
    response.status_code == 401
)


# ========================================
# 11. LOGOUT
# ========================================

response = requests.post(
    f"{BASE_URL}/logout",
    headers={
        "Authorization": f"Bearer {token}"
    }
)

test(
    "Logout successful",
    response.status_code == 200
)


# ========================================
# 12. SESSION AFTER LOGOUT
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {token}"
    }
)

test(
    "Revoked session rejected",
    response.status_code == 401
)


# ========================================
# 13. NEW LOGIN
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": USERNAME,
        "password": PASSWORD
    }
)

test(
    "Second login successful",
    response.status_code == 200
)


new_token = None

if response.status_code == 200:

    new_token = response.json().get(
        "token"
    )


# ========================================
# 14. NEW TOKEN DIFFERENT
# ========================================

test(
    "New login generates new token",
    new_token is not None
    and new_token != token
)


# ========================================
# 15. NEW SESSION
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {new_token}"
    }
)

test(
    "New session accepted",
    response.status_code == 200
)


# ========================================
# CLEANUP
# ========================================

if new_token:

    requests.post(
        f"{BASE_URL}/logout",
        headers={
            "Authorization":
            f"Bearer {new_token}"
        }
    )


# ========================================
# SUMMARY
# ========================================

print()
print("========================================")
print("             TEST SUMMARY")
print("========================================")

print(
    f"Passed: {passed}"
)

print(
    f"Failed: {failed}"
)

print(
    f"Total:  {passed + failed}"
)

print("========================================")


if failed == 0:

    print()
    print("ALL API TESTS PASSED")
    print("DPAS V0.5 API: OK")

else:

    print()
    print("API TESTS FAILED")

    raise SystemExit(1)
