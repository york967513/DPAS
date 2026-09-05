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
print("     DPAS V0.3 FULL AUTH TEST")
print("================================")


# Initialize database
initialize_database()

print()
print("[1] Database initialized")


# Get user
user = get_user(
    USERNAME
)

if user is None:
    print("[ERROR] User not found")
    raise SystemExit(1)


print("[2] User found")


# Get authentication salt
auth_salt = user[6]

if auth_salt is None:
    print("[ERROR] Authentication salt not found")
    raise SystemExit(1)


print("[3] Authentication salt found")


# SERVER
# Generate authentication challenge
request = create_login_challenge(
    USERNAME
)

if request is None:
    print("[ERROR] Challenge creation failed")
    raise SystemExit(1)


challenge = request["challenge"]


print("[4] Server generated challenge")

print(
    "    Challenge:",
    challenge
)


# CLIENT
# Decrypt private key and sign challenge
signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)


print("[5] Client created signature")


# SERVER
# Verify signature
result = verify_login_response(
    USERNAME,
    challenge,
    signature
)


print(
    "[6] Server verification:",
    result
)


if result:

    print()
    print("================================")
    print("       AUTHENTICATION OK")
    print("================================")

else:

    print()
    print("================================")
    print("       AUTHENTICATION FAILED")
    print("================================")

    raise SystemExit(1)

