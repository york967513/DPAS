import os
from app.database import initialize_database
from app.auth_manager import login


USERNAME = "V03Test"

CORRECT_PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

WRONG_PASSWORD = os.getenv("DPAS_WRONG_PASSWORD", "DPAS_Wrong_Test_Password_2026!")


print("================================")
print("       DPAS V0.3 LOGIN TEST")
print("================================")


# Initialize database
initialize_database()

print("[1] Database: OK")


# Correct password
result_correct = login(
    USERNAME,
    CORRECT_PASSWORD
)

print(
    "[2] Correct password:",
    result_correct
)


# Wrong password
result_wrong = login(
    USERNAME,
    WRONG_PASSWORD
)

print(
    "[3] Wrong password:",
    result_wrong
)


if result_correct and not result_wrong:

    print()
    print("================================")
    print("       LOGIN TEST PASSED")
    print("================================")

else:

    print()
    print("================================")
    print("       LOGIN TEST FAILED")
    print("================================")

    raise SystemExit(1)
