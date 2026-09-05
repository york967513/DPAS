import os
import requests
import urllib3


BASE_URL = "https://127.0.0.1:8443"

USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


# Self-signed certificate is expected
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


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
print("          DPAS V0.6 TLS TEST")
print("========================================")


# ========================================
# 01. HTTPS HEALTH
# ========================================

try:

    response = requests.get(
        f"{BASE_URL}/health",
        verify=False,
        timeout=5
    )

    test(
        "HTTPS connection",
        response.status_code == 200
    )

except Exception as error:

    print("[ERROR] HTTPS server unavailable")
    print(error)

    raise SystemExit(1)


# ========================================
# 02. HEALTH CONTENT
# ========================================

if response.status_code == 200:

    data = response.json()

else:

    data = {}


test(
    "Health response valid",
    data.get("status") == "ok"
)


test(
    "DPAS service identified",
    data.get("service") == "DPAS"
)


# ========================================
# 03. HTTPS LOGIN
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": USERNAME,
        "password": PASSWORD
    },
    verify=False,
    timeout=5
)

test(
    "HTTPS login successful",
    response.status_code == 200
)


token = None

if response.status_code == 200:

    token = response.json().get(
        "token"
    )


# ========================================
# 04. TOKEN GENERATED
# ========================================

test(
    "Session token generated",
    token is not None
    and len(token) > 0
)


# ========================================
# 05. HTTPS SESSION
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": f"Bearer {token}"
    },
    verify=False,
    timeout=5
)

test(
    "HTTPS session accepted",
    response.status_code == 200
)


# ========================================
# 06. USERNAME
# ========================================

if response.status_code == 200:

    data = response.json()

    session_username = data.get(
        "username"
    )

else:

    session_username = None


test(
    "Correct username returned",
    session_username == USERNAME
)


# ========================================
# 07. WRONG PASSWORD
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": USERNAME,
        "password": os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")
    },
    verify=False,
    timeout=5
)

test(
    "Wrong password rejected",
    response.status_code == 401
)


# ========================================
# 08. INVALID TOKEN
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization": "Bearer INVALID_TOKEN"
    },
    verify=False,
    timeout=5
)

test(
    "Invalid token rejected",
    response.status_code == 401
)


# ========================================
# 09. MODIFIED TOKEN
# ========================================

modified_token = (
    token[:-1] + "A"
)

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization":
        f"Bearer {modified_token}"
    },
    verify=False,
    timeout=5
)

test(
    "Modified token rejected",
    response.status_code == 401
)


# ========================================
# 10. LOGOUT
# ========================================

response = requests.post(
    f"{BASE_URL}/logout",
    headers={
        "Authorization":
        f"Bearer {token}"
    },
    verify=False,
    timeout=5
)

test(
    "HTTPS logout successful",
    response.status_code == 200
)


# ========================================
# 11. REVOKED TOKEN
# ========================================

response = requests.get(
    f"{BASE_URL}/session",
    headers={
        "Authorization":
        f"Bearer {token}"
    },
    verify=False,
    timeout=5
)

test(
    "Revoked token rejected",
    response.status_code == 401
)


# ========================================
# 12. NEW LOGIN
# ========================================

response = requests.post(
    f"{BASE_URL}/login",
    json={
        "username": USERNAME,
        "password": PASSWORD
    },
    verify=False,
    timeout=5
)

test(
    "Second HTTPS login successful",
    response.status_code == 200
)


new_token = None

if response.status_code == 200:

    new_token = response.json().get(
        "token"
    )


# ========================================
# 13. NEW TOKEN
# ========================================

test(
    "New session token generated",
    new_token is not None
)


test(
    "New token differs from old token",
    new_token is not None
    and new_token != token
)


# ========================================
# 14. CLEANUP
# ========================================

if new_token:

    requests.post(
        f"{BASE_URL}/logout",
        headers={
            "Authorization":
            f"Bearer {new_token}"
        },
        verify=False,
        timeout=5
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
    print("ALL TLS TESTS PASSED")
    print("DPAS V0.6 TLS: OK")

else:

    print()
    print("TLS TESTS FAILED")

    raise SystemExit(1)
