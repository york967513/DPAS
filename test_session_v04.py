from app.database import (
    initialize_database
)

from app.session_manager import (
    create_user_session,
    validate_session,
    get_session_username,
    logout
)


USERNAME = "V03Test"


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
print("       DPAS V0.4 SESSION TEST")
print("========================================")


initialize_database()


# ----------------------------------------
# 01. CREATE SESSION
# ----------------------------------------

token = create_user_session(
    USERNAME
)

test(
    "Session created",
    bool(token)
)


print(
    "    Token length:",
    len(token)
)


# ----------------------------------------
# 02. TOKEN IS RANDOM
# ----------------------------------------

token2 = create_user_session(
    USERNAME
)

test(
    "Second token is different",
    token != token2
)


# ----------------------------------------
# 03. VALID TOKEN
# ----------------------------------------

test(
    "Valid session accepted",
    validate_session(token)
)


# ----------------------------------------
# 04. SECOND VALID TOKEN
# ----------------------------------------

test(
    "Second valid session accepted",
    validate_session(token2)
)


# ----------------------------------------
# 05. WRONG TOKEN
# ----------------------------------------

test(
    "Wrong token rejected",
    not validate_session(
        "DefinitelyNotAValidSessionToken"
    )
)


# ----------------------------------------
# 06. USERNAME
# ----------------------------------------

test(
    "Session belongs to correct user",
    get_session_username(token)
    == USERNAME
)


# ----------------------------------------
# 07. LOGOUT
# ----------------------------------------

logout_result = logout(
    token
)

test(
    "Logout successful",
    logout_result
)


# ----------------------------------------
# 08. REVOKED SESSION
# ----------------------------------------

test(
    "Revoked session rejected",
    not validate_session(token)
)


# ----------------------------------------
# 09. OTHER SESSION STILL VALID
# ----------------------------------------

test(
    "Other session remains valid",
    validate_session(token2)
)


# ----------------------------------------
# 10. LOGOUT SECOND SESSION
# ----------------------------------------

logout(
    token2
)

test(
    "Second session revoked",
    not validate_session(token2)
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
    print("ALL SESSION TESTS PASSED")
    print("DPAS V0.4 SESSION MANAGER: OK")

else:

    print()
    print("SESSION TESTS FAILED")

    raise SystemExit(1)