import os
import requests

BASE_URL = "http://127.0.0.1:8000"

USERNAME = "V07Normal3"
WRONG_PASSWORD = os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")

print("=" * 70)
print("DPAS V0.8.1 AUTHENTICATION / LOCKOUT BYPASS TEST")
print("=" * 70)

print()
print("[1] INITIAL ACCOUNT STATE")

from app.database import get_user

user = get_user(USERNAME)

if user is None:
    print("[FAIL] Test user does not exist")
    raise SystemExit(1)

print("USERNAME:", USERNAME)
print("FAILED ATTEMPTS:", user[4])
print("LOCKED UNTIL:", user[5])

print()
print("[2] RESET ACCOUNT STATE")

from app.database import reset_failed_attempts

reset_failed_attempts(USERNAME)

user = get_user(USERNAME)

print("FAILED ATTEMPTS:", user[4])
print("LOCKED UNTIL:", user[5])

if user[4] == 0 and user[5] is None:
    print("[PASS] Account reset")
else:
    print("[FAIL] Account could not be reset")
    raise SystemExit(1)


print()
print("[3] DIRECT authenticate_user() BASELINE")

from app.auth import authenticate_user

for i in range(1, 6):

    result = authenticate_user(
        USERNAME,
        WRONG_PASSWORD
    )

    user = get_user(USERNAME)

    print(
        f"ATTEMPT {i}:",
        "AUTH RESULT:",
        result,
        "| FAILED ATTEMPTS:",
        user[4],
        "| LOCKED UNTIL:",
        user[5]
    )

print()
print("[4] DATABASE LOCKOUT STATE")

user = get_user(USERNAME)

if user[4] >= 5 and user[5] is not None:
    print("[PASS] Direct authentication triggers lockout")
else:
    print("[FAIL] Direct authentication did not create lockout")


print()
print("[5] RESET BEFORE API TEST")

reset_failed_attempts(USERNAME)

user = get_user(USERNAME)

print(
    "FAILED ATTEMPTS:",
    user[4]
)

print(
    "LOCKED UNTIL:",
    user[5]
)


print()
print("[6] API /login WRONG PASSWORD ATTEMPTS")

for i in range(1, 8):

    response = requests.post(
        f"{BASE_URL}/login",
        json={
            "username": USERNAME,
            "password": WRONG_PASSWORD
        }
    )

    user = get_user(USERNAME)

    print()
    print(
        f"API ATTEMPT {i}"
    )

    print(
        "HTTP STATUS:",
        response.status_code
    )

    print(
        "BODY:",
        response.text
    )

    print(
        "FAILED ATTEMPTS:",
        user[4]
    )

    print(
        "LOCKED UNTIL:",
        user[5]
    )


print()
print("[7] ANALYSIS")

user = get_user(USERNAME)

if user[4] >= 5 and user[5] is not None:

    print(
        "[PASS] API login participates in account lockout"
    )

else:

    print(
        "[FAIL] POSSIBLE LOCKOUT BYPASS"
    )

    print(
        "The API /login authentication chain does not appear"
    )

    print(
        "to update failed_attempts / locked_until."
    )


print()
print("[8] CLEANUP")

reset_failed_attempts(USERNAME)

user = get_user(USERNAME)

print(
    "FAILED ATTEMPTS:",
    user[4]
)

print(
    "LOCKED UNTIL:",
    user[5]
)

print()
print("=" * 70)
print("V0.8.1 AUTHENTICATION / LOCKOUT BYPASS TEST FINISHED")
print("=" * 70)

