import os
import sqlite3

from datetime import datetime, timezone, timedelta

from app.database import (
    initialize_database,
    get_user
)

from app.auth_manager import login

from app.server_auth import (
    create_login_challenge,
    verify_login_response
)

from app.client_auth import (
    create_client_signature
)


USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")
WRONG_PASSWORD = os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")


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
print("       DPAS V0.3 SECURITY SUITE")
print("========================================")


initialize_database()


# --------------------------------------------------
# USER CHECK
# --------------------------------------------------

user = get_user(USERNAME)

if user is None:
    print()
    print("[ERROR] Test user does not exist.")
    print("Create V03Test before running this suite.")
    raise SystemExit(1)


auth_salt = user[6]


# --------------------------------------------------
# 01. CORRECT PASSWORD
# --------------------------------------------------

result = login(
    USERNAME,
    PASSWORD
)

test(
    "Correct password",
    result is True
)


# --------------------------------------------------
# 02. WRONG PASSWORD
# --------------------------------------------------

result = login(
    USERNAME,
    WRONG_PASSWORD
)

test(
    "Wrong password rejected",
    result is False
)


# --------------------------------------------------
# 03. UNKNOWN USER
# --------------------------------------------------

result = login(
    "DefinitelyNotExistingUser",
    PASSWORD
)

test(
    "Unknown user rejected",
    result is False
)


# --------------------------------------------------
# 04. WRONG CHALLENGE
# --------------------------------------------------

request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)

fake_challenge = challenge[:-4] + "AAAA"

result = verify_login_response(
    USERNAME,
    fake_challenge,
    signature
)

test(
    "Wrong challenge rejected",
    result is False
)


# --------------------------------------------------
# 05. MODIFIED SIGNATURE
# --------------------------------------------------

request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)

# Modify the signature
modified_signature = (
    signature[:-4] + "AAAA"
)

result = verify_login_response(
    USERNAME,
    challenge,
    modified_signature
)

test(
    "Modified signature rejected",
    result is False
)


# --------------------------------------------------
# 06. REPLAY ATTACK
# --------------------------------------------------

request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)

first_result = verify_login_response(
    USERNAME,
    challenge,
    signature
)

second_result = verify_login_response(
    USERNAME,
    challenge,
    signature
)

test(
    "Initial authentication accepted",
    first_result is True
)

test(
    "Replay attack rejected",
    second_result is False
)


# --------------------------------------------------
# 07. EXPIRED CHALLENGE
# --------------------------------------------------

request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)

# Artificially age the challenge
connection = sqlite3.connect(
    "data/dpas.db"
)

old_time = (
    datetime.now(timezone.utc)
    - timedelta(seconds=120)
).isoformat()

connection.execute(
    """
    UPDATE challenges
    SET created_at = ?
    WHERE username = ?
      AND challenge = ?
    """,
    (
        old_time,
        USERNAME,
        challenge
    )
)

connection.commit()
connection.close()


result = verify_login_response(
    USERNAME,
    challenge,
    signature
)

test(
    "Expired challenge rejected",
    result is False
)


# --------------------------------------------------
# 08. MISSING PRIVATE KEY
# --------------------------------------------------

import app.auth_manager as auth_manager


original_create_client_signature = (
    auth_manager.create_client_signature
)


def fake_create_client_signature(
    username,
    password,
    salt,
    challenge
):
    raise FileNotFoundError(
        "Private key not found"
    )


auth_manager.create_client_signature = (
    fake_create_client_signature
)


result = login(
    USERNAME,
    PASSWORD
)


auth_manager.create_client_signature = (
    original_create_client_signature
)


test(
    "Missing private key rejected",
    result is False
)


# --------------------------------------------------
# 09. MISSING PUBLIC KEY
# --------------------------------------------------

connection = sqlite3.connect(
    "data/dpas.db"
)

connection.execute(
    """
    UPDATE users
    SET public_key = NULL
    WHERE username = ?
    """,
    (USERNAME,)
)

connection.commit()
connection.close()


result = login(
    USERNAME,
    PASSWORD
)


# Restore public key
connection = sqlite3.connect(
    "data/dpas.db"
)

# Get original public key from user object
original_public_key = user[7]

connection.execute(
    """
    UPDATE users
    SET public_key = ?
    WHERE username = ?
    """,
    (
        original_public_key,
        USERNAME
    )
)

connection.commit()
connection.close()


test(
    "Missing public key rejected",
    result is False
)


# --------------------------------------------------
# 10. MULTIPLE CONSECUTIVE LOGINS
# --------------------------------------------------

results = []

for i in range(5):

    result = login(
        USERNAME,
        PASSWORD
    )

    results.append(result)


test(
    "Five consecutive logins accepted",
    all(results)
)


# --------------------------------------------------
# SUMMARY
# --------------------------------------------------

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
    print("ALL SECURITY TESTS PASSED")
    print("DPAS V0.3 SECURITY SUITE: OK")

else:

    print()
    print("SECURITY TESTS FAILED")
    print("DPAS V0.3 REQUIRES FIXES")

    raise SystemExit(1)
