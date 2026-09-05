import os
from app.database import (
    initialize_database,
    get_user
)

from app.server_auth import (
    create_login_challenge
)

from app.client_auth import (
    create_client_signature
)


USERNAME = "V03Test"

CORRECT_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

WRONG_PASSWORD = os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")


print("================================")
print(" DPAS V0.3 WRONG PASSWORD TEST")
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

print("[2] User: OK")


request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

print("[3] Challenge generated")


try:

    signature = create_client_signature(
        USERNAME,
        WRONG_PASSWORD,
        auth_salt,
        challenge
    )

    print(
        "[4] Wrong password produced signature:",
        True
    )

    print()
    print("TEST FAILED")

    raise SystemExit(1)

except Exception as error:

    print(
        "[4] Wrong password rejected: True"
    )

    print(
        "[5] Exception type:",
        type(error).__name__
    )


print()
print("================================")
print(" WRONG PASSWORD TEST PASSED")
print("================================")
