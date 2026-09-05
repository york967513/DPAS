import os
import sqlite3

from app.database import initialize_database
from app.auth import register_user
from app.client_storage import save_private_key


USERNAME = "V03Test"

PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


print("=== DPAS V0.3 Registration ===")


# Initialize database
initialize_database()

print("Database: OK")


# Register user
result = register_user(
    USERNAME,
    PASSWORD
)


if result is None:
    print("Registration: FAILED")
    raise SystemExit(1)


print("Registration: OK")


# Get encrypted private key
encrypted_private_key = result[
    "encrypted_private_key"
]


print(
    "Encrypted private key length:",
    len(encrypted_private_key)
)


# Store encrypted private key on client
save_private_key(
    USERNAME,
    encrypted_private_key
)


print("Client private key storage: OK")


# Check server database
connection = sqlite3.connect(
    "data/dpas.db"
)


user = connection.execute(
    """
    SELECT
        username,
        public_key
    FROM users
    WHERE username = ?
    """,
    (USERNAME,)
).fetchone()


connection.close()


if user is None:
    print("Database user lookup: FAILED")
    raise SystemExit(1)


print("Username:", user[0])

print(
    "Public key length:",
    len(user[1])
)


print("=== V0.3 Registration Test PASSED ===")
