import os
from app.database import (
    initialize_database,
    get_user
)

from app.server_auth import (
    create_login_challenge,
    verify_login_response
)

from app.client_auth import (
    create_client_signature
)


USERNAME = "V03Test"

PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


print("================================")
print("    DPAS V0.3 REPLAY TEST")
print("================================")


initialize_database()

print("[1] Database: OK")


user = get_user(
    USERNAME
)

if user is None:
    print("[ERROR] User not found")
    raise SystemExit(1)


auth_salt = user[6]

if auth_salt is None:
    print("[ERROR] Auth salt not found")
    raise SystemExit(1)


print("[2] User: OK")


# --------------------------------
# FIRST AUTHENTICATION
# --------------------------------

request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

print("[3] Challenge generated")


signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)

print("[4] Signature generated")


first_result = verify_login_response(
    USERNAME,
    challenge,
    signature
)

print(
    "[5] First authentication:",
    first_result
)


# --------------------------------
# REPLAY ATTACK
# --------------------------------

second_result = verify_login_response(
    USERNAME,
    challenge,
    signature
)

print(
    "[6] Replay attempt:",
    second_result
)


if first_result and not second_result:

    print()
    print("================================")
    print("   REPLAY PROTECTION PASSED")
    print("================================")

else:

    print()
    print("================================")
    print("   REPLAY PROTECTION FAILED")
    print("================================")

    raise SystemExit(1)
