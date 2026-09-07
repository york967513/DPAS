import secrets

from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user, is_user_locked
from app.database import delete_user, get_user, reset_failed_attempts
from app.rate_limiter import clear_rate_limits


RUN_ID = secrets.token_hex(4)

PASSWORD = "DPAS_Test_Password_2026!"

LOCKOUT_USER = f"V0828Lockout_{RUN_ID}"
RATE_USER = f"V0828RateLimit_{RUN_ID}"

BURST_COUNT = 35

client = TestClient(app)

failures = 0


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def cleanup():
    clear_rate_limits()

    for username in [
        LOCKOUT_USER,
        RATE_USER
    ]:
        try:
            reset_failed_attempts(username)
        except Exception:
            pass

        try:
            delete_user(username)
        except Exception:
            pass


def check_rate_limit_results(label, statuses):
    count_429 = statuses.count(429)

    print(f"[INFO] Responses: {statuses}")
    print(f"[INFO] HTTP 429 responses: {count_429}")

    if count_429 > 0:
        pass_check(
            f"{label}: HTTP 429 rate limiting triggered"
        )
    else:
        fail_check(
            label,
            "no HTTP 429 received after exceeding 30 requests"
        )


try:
    print("=" * 70)
    print("DPAS V0.8.28 RATE LIMIT / AUTHENTICATION ABUSE TEST")
    print("=" * 70)

    print()
    print(f"[SETUP] Unique test namespace: {RUN_ID}")
    print(f"[SETUP] Lockout control user: {LOCKOUT_USER}")
    print(f"[SETUP] Rate-limit test user: {RATE_USER}")
    print(f"[SETUP] Rate limit: 30 requests / 60 seconds")
    print(f"[SETUP] Burst size: {BURST_COUNT}")

    cleanup()

    # ============================================================
    # 1. CREATE TEST USERS
    # ============================================================

    print()
    print("[1] TEST USERS")

    lockout_result = register_user(
        LOCKOUT_USER,
        PASSWORD
    )

    rate_result = register_user(
        RATE_USER,
        PASSWORD
    )

    if lockout_result is not None:
        pass_check("Lockout control user registered")
    else:
        fail_check(
            "Lockout control user registration",
            "registration returned None"
        )

    if rate_result is not None:
        pass_check("Rate-limit test user registered")
    else:
        fail_check(
            "Rate-limit test user registration",
            "registration returned None"
        )

    # ============================================================
    # 2. ACCOUNT LOCKOUT CONTROL
    # ============================================================

    print()
    print("[2] ACCOUNT LOCKOUT CONTROL")

    clear_rate_limits()

    for attempt in range(5):
        response = client.post(
            "/login",
            json={
                "username": LOCKOUT_USER,
                "password": "Wrong_Password_2026!"
            }
        )

        if response.status_code != 401:
            fail_check(
                "Failed-login control",
                (
                    f"attempt {attempt + 1}: expected HTTP 401, "
                    f"got HTTP {response.status_code}"
                )
            )
            break
    else:
        if is_user_locked(LOCKOUT_USER):
            pass_check(
                "Per-user lockout activates after five failed logins"
            )
        else:
            fail_check(
                "Per-user lockout control",
                "user was not locked after five failed logins"
            )

    # ============================================================
    # 3. UNIQUE USERNAME BURST
    # ============================================================

    print()
    print("[3] UNIQUE USERNAME BURST")

    clear_rate_limits()

    statuses = []

    for index in range(BURST_COUNT):
        username = f"V0828Unknown_{RUN_ID}_{index}"

        response = client.post(
            "/auth/challenge",
            json={
                "username": username
            }
        )

        statuses.append(response.status_code)

    check_rate_limit_results(
        "Unique-username burst",
        statuses
    )

    if statuses[:30].count(401) == 30:
        pass_check(
            "First 30 unique-username requests reached endpoint"
        )
    else:
        fail_check(
            "Rate-limit threshold",
            "the first 30 requests did not all reach the endpoint"
        )

    # ============================================================
    # 4. SAME USERNAME BURST
    # ============================================================

    print()
    print("[4] SAME USERNAME BURST")

    clear_rate_limits()

    same_user_statuses = []

    for _ in range(BURST_COUNT):
        response = client.post(
            "/auth/challenge",
            json={
                "username": RATE_USER
            }
        )

        same_user_statuses.append(
            response.status_code
        )

    check_rate_limit_results(
        "Same-user burst",
        same_user_statuses
    )

    if same_user_statuses[:30].count(200) == 30:
        pass_check(
            "First 30 same-user challenge requests were accepted"
        )
    else:
        fail_check(
            "Same-user rate-limit threshold",
            "the first 30 requests were not accepted"
        )

    # ============================================================
    # 5. RETRY-AFTER HEADER
    # ============================================================

    print()
    print("[5] RETRY-AFTER HEADER")

    limited_response = client.post(
        "/auth/challenge",
        json={
            "username": RATE_USER
        }
    )

    if (
        limited_response.status_code == 429
        and limited_response.headers.get("Retry-After") == "60"
    ):
        pass_check(
            "Rate-limited response includes Retry-After: 60"
        )
    else:
        fail_check(
            "Retry-After header",
            (
                f"expected HTTP 429 with Retry-After: 60, "
                f"got HTTP {limited_response.status_code} "
                f"with Retry-After={limited_response.headers.get('Retry-After')!r}"
            )
        )

    # ============================================================
    # 6. PASSWORD FAILURE COUNTER ISOLATION
    # ============================================================

    print()
    print("[6] RESOURCE / ACCOUNTING EFFECT")

    user_after_burst = get_user(RATE_USER)

    if user_after_burst is None:
        fail_check(
            "Rate-limit resource test",
            "rate-limit test user disappeared unexpectedly"
        )
    else:
        failed_attempts = user_after_burst[4]

        print(
            f"[INFO] failed_attempts after challenge burst: "
            f"{failed_attempts}"
        )

        if failed_attempts == 0:
            pass_check(
                "Challenge burst does not alter password failure counter"
            )
        else:
            fail_check(
                "Challenge burst isolation",
                (
                    "challenge traffic unexpectedly changed the "
                    "password failure counter"
                )
            )

finally:
    print()
    print("[CLEANUP] Removing V0.8.28 test users")
    cleanup()

    print()
    print("=" * 70)

    if failures == 0:
        print("V0.8.28 RATE LIMIT / AUTHENTICATION ABUSE TEST PASSED")
    else:
        print("V0.8.28 RATE LIMIT / AUTHENTICATION ABUSE TEST FAILED")

    print("=" * 70)

raise SystemExit(1 if failures else 0)
