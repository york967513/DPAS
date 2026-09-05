import os
from app.database import (
    initialize_database
)

from app.auth_manager import (
    login
)

from app.session_manager import (
    validate_session,
    get_session_username,
    logout
)


USERNAME = "V03Test"

CORRECT_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

WRONG_PASSWORD = os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")


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
print("   DPAS V0.4 LOGIN + SESSION TEST")
print("========================================")


initialize_database()


# ----------------------------------------
# 01. CORRECT LOGIN
# ----------------------------------------

token = login(
    USERNAME,
    CORRECT_PASSWORD
)

test(
    "Correct login returns session token",
    token is not None
)


# ----------------------------------------
# 02. SESSION VALID
# ----------------------------------------

test(
    "Returned session is valid",
    validate_session(token)
)


# ----------------------------------------
# 03. SESSION USER
# ----------------------------------------

test(
    "Session belongs to correct user",
    get_session_username(token)
    == USERNAME
)


# ----------------------------------------
# 04. WRONG PASSWORD
# ----------------------------------------

wrong_token = login(
    USERNAME,
    WRONG_PASSWORD
)

test(
    "Wrong password does not create session",
    wrong_token is None
)


# ----------------------------------------
# 05. UNKNOWN USER
# ----------------------------------------

unknown_token = login(
    "UnknownUser12345",
    CORRECT_PASSWORD
)

test(
    "Unknown user does not create session",
    unknown_token is None
)


# ----------------------------------------
# 06. LOGOUT
# ----------------------------------------

logout_result = logout(
    token
)

test(
    "Logout successful",
    logout_result
)


# ----------------------------------------
# 07. SESSION REVOKED
# ----------------------------------------

test(
    "Logged out session rejected",
    not validate_session(token)
)


# ----------------------------------------
# 08. NEW LOGIN
# ----------------------------------------

token2 = login(
    USERNAME,
    CORRECT_PASSWORD
)

test(
    "Second login creates new session",
    token2 is not None
)


# ----------------------------------------
# 09. TOKENS DIFFER
# ----------------------------------------

test(
    "New login receives different token",
    token2 != token
)


# ----------------------------------------
# 10. NEW SESSION VALID
# ----------------------------------------

test(
    "New session is valid",
    validate_session(token2)
)


# ----------------------------------------
# CLEANUP
# ----------------------------------------

logout(token2)


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
    print("ALL INTEGRATION TESTS PASSED")
    print("DPAS V0.4 AUTHENTICATION: OK")

else:

    print()
    print("INTEGRATION TESTS FAILED")

    raise SystemExit(1)
