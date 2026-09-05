import os
from app.database import get_user
from app.dpas_client import DPASClient

BASE_URL = "https://127.0.0.1:8443"
USERNAME = "V03Test"
PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

user = get_user(USERNAME)

if user is None:
    print("[FAIL] User not found")
    raise SystemExit(1)

client = DPASClient(
    BASE_URL,
    USERNAME,
    PASSWORD,
    user[6],
    False
)

if client.authenticate():
    print("[PASS] V03Test authentication")
else:
    print("[FAIL] V03Test authentication")

