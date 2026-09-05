import os
import sqlite3

from app.server import AuthenticationServer
from app.client import AuthenticationClient


USERNAME = "V02Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")


connection = sqlite3.connect("data/dpas.db")

user = connection.execute(
    """
    SELECT auth_salt
    FROM users
    WHERE username = ?
    """,
    (USERNAME,)
).fetchone()

connection.close()


salt = user[0]


server = AuthenticationServer()


client = AuthenticationClient(
    USERNAME,
    PASSWORD,
    salt
)


print("=== DPAS V0.2 Test ===")


# Step 1
request = server.start_authentication(USERNAME)

print("Username:", request["username"])
print("Challenge:", request["challenge"].hex())


# Step 2
response = client.create_response(
    request["challenge"]
)

print("Response:", response.hex())


# Step 3
# Server verifies response
#
# For V0.2 the server needs the derived key.
# This is intentionally temporary and will be
# redesigned in the next version.

from app.password import derive_key

key = derive_key(
    PASSWORD,
    salt
)


result = server.verify_authentication(
    USERNAME,
    response,
    key
)


print("Authentication:", result)

print("Replay attack:", server.verify_authentication(
    USERNAME,
    response,
    key
))
