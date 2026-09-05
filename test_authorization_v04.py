import os
from app.auth_manager import login

from app.authorization import (
    require_auth,
    require_user
)

from app.session_manager import (
    logout
)


USERNAME = "V03Test"

PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

WRONG_USERNAME = "AnotherUser"


passed = 0
failed = 0


def test(
    name,
    result
):
    global passed
    global failed

    if result:
        print(
            f"[PASS] {name}"
        )
        passed += 1

    else:
        print(
            f"[FAIL] {name}"
        )
        failed += 1


print("========================================")
print("      DPAS V0.4 AUTHORIZATION TEST")
print("========================================")


# ----------------------------------------
# 01. LOGIN
# ----------------------------------------

token = login(
    USERNAME,
    PASSWORD
)

test(
    "Login successful",
    token is not None
)


# ----------------------------------------
# 02. AUTHENTICATED USER
# ----------------------------------------

authenticated_user = require_auth(
    token
)

test(
    "Authenticated session accepted",
    authenticated_user == USERNAME
)


# ----------------------------------------
# 03. CORRECT USER
# ----------------------------------------

test(
    "Correct user authorized",
    require_user(
        token,
        USERNAME
    )
)


# ----------------------------------------
# 04. WRONG USER
# ----------------------------------------

test(
    "Different user rejected",
    not require_user(
        token,
        WRONG_USERNAME
    )
)


# ----------------------------------------
# 05. EMPTY TOKEN
# ----------------------------------------

test(
    "Empty token rejected",
    require_auth("") is None
)


# ----------------------------------------
# 06. INVALID TOKEN
# ----------------------------------------

test(
    "Invalid token rejected",
    require_auth(
        "INVALID_TOKEN_123"
    ) is None
)


# ----------------------------------------
# 07. MODIFIED TOKEN
# ----------------------------------------

modified_token = (
    token[:-1] + "A"
)

test(
    "Modified token rejected",
    require_auth(
        modified_token
    ) is None
)


# ----------------------------------------
# 08. LOGOUT
# ----------------------------------------

test(
    "Logout successful",
    logout(token)
)


# ----------------------------------------
# 09. REVOKED TOKEN
# ----------------------------------------

test(
    "Revoked token rejected",
    require_auth(token) is None
)


# ----------------------------------------
# 10. REVOKED USER AUTHORIZATION
# ----------------------------------------

test(
    "Revoked user authorization rejected",
    not require_user(
        token,
        USERNAME
    )
)


# ----------------------------------------
# SUMMARY
# ----------------------------------------

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
    print("ALL AUTHORIZATION TESTS PASSED")
    print("DPAS V0.4 AUTHORIZATION: OK")

else:

    print()
    print("AUTHORIZATION TESTS FAILED")

    raise SystemExit(1)
