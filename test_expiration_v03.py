import os
import sqlite3

from datetime import datetime, timezone, timedelta

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
print("   DPAS V0.3 EXPIRATION TEST")
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


# Generate challenge
request = create_login_challenge(
    USERNAME
)

challenge = request["challenge"]

print("[3] Challenge generated")


# Create valid signature
signature = create_client_signature(
    USERNAME,
    PASSWORD,
    auth_salt,
    challenge
)

print("[4] Signature generated")


# Find challenge in database
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


print("[5] Challenge artificially aged to 120 seconds")


# Try authentication
result = verify_login_response(
    USERNAME,
    challenge,
    signature
)

print(
    "[6] Expired challenge accepted:",
    result
)


if not result:

    print()
    print("================================")
    print("   EXPIRATION TEST PASSED")
    print("================================")

else:

    print()
    print("================================")
    print("   EXPIRATION TEST FAILED")
    print("================================")

    raise SystemExit(1)
