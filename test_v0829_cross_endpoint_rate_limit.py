from fastapi.testclient import TestClient

from app.api import app
from app.rate_limiter import clear_rate_limits


REQUESTS_PER_ENDPOINT = 11

client = TestClient(app)

failures = 0


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def expect_all(statuses, expected, label):
    if statuses == [expected] * len(statuses):
        pass_check(label)
    else:
        fail_check(
            label,
            f"expected all {expected}, got {statuses}"
        )


try:
    print("=" * 70)
    print("DPAS V0.8.29 CROSS-ENDPOINT RATE-LIMIT BYPASS TEST")
    print("=" * 70)

    print()
    print(
        f"[SETUP] Requests per endpoint: "
        f"{REQUESTS_PER_ENDPOINT}"
    )

    print(
        "[SETUP] Total requests: 33"
    )

    clear_rate_limits()

    # ============================================================
    # 1. ROTATE AUTHENTICATION ENDPOINTS
    #
    # All requests originate from the same TestClient IP and must
    # share one authentication rate-limit bucket.
    # ============================================================

    print()
    print("[1] CROSS-ENDPOINT ROTATION")

    statuses = []

    for index in range(REQUESTS_PER_ENDPOINT):
        response = client.post(
            "/auth/challenge",
            json={
                "username": f"V0829UnknownChallenge_{index}"
            }
        )

        statuses.append(
            response.status_code
        )

    for index in range(REQUESTS_PER_ENDPOINT):
        response = client.post(
            "/login",
            json={
                "username": f"V0829UnknownLogin_{index}",
                "password": "Wrong_Password_2026!"
            }
        )

        statuses.append(
            response.status_code
        )

    for index in range(REQUESTS_PER_ENDPOINT):
        response = client.post(
            "/auth/verify",
            json={
                "username": f"V0829UnknownVerify_{index}",
                "challenge": "invalid-challenge",
                "signature": "invalid-signature"
            }
        )

        statuses.append(
            response.status_code
        )

    print(
        f"[INFO] Responses: {statuses}"
    )

    count_429 = statuses.count(429)

    print(
        f"[INFO] HTTP 429 responses: {count_429}"
    )

    if count_429 > 0:
        pass_check(
            "Endpoint rotation is blocked by shared authentication rate limit"
        )
    else:
        fail_check(
            "Cross-endpoint rate-limit protection",
            "33 authentication requests produced no HTTP 429"
        )

    # ============================================================
    # 2. THRESHOLD
    # ============================================================

    print()
    print("[2] SHARED RATE-LIMIT THRESHOLD")

    clear_rate_limits()

    first_30 = []

    for index in range(30):
        endpoint = (
            "/auth/challenge"
            if index % 3 == 0
            else "/login"
            if index % 3 == 1
            else "/auth/verify"
        )

        if endpoint == "/auth/challenge":
            response = client.post(
                endpoint,
                json={
                    "username": f"V0829Threshold_{index}"
                }
            )
        elif endpoint == "/login":
            response = client.post(
                endpoint,
                json={
                    "username": f"V0829Threshold_{index}",
                    "password": "Wrong_Password_2026!"
                }
            )
        else:
            response = client.post(
                endpoint,
                json={
                    "username": f"V0829Threshold_{index}",
                    "challenge": "invalid",
                    "signature": "invalid"
                }
            )

        first_30.append(
            response.status_code
        )

    print(
        f"[INFO] First 30 responses: {first_30}"
    )

    if all(status in (200, 401) for status in first_30):
        pass_check(
            "First 30 mixed authentication requests were accepted"
        )
    else:
        fail_check(
            "Shared rate-limit threshold",
            "a request was limited before the 30-request threshold"
        )

    # ============================================================
    # 3. 31ST REQUEST
    # ============================================================

    print()
    print("[3] 31ST AUTHENTICATION REQUEST")

    response = client.post(
        "/auth/challenge",
        json={
            "username": "V0829ThresholdFinal"
        }
    )

    print(
        f"[INFO] 31st response: HTTP {response.status_code}"
    )

    if response.status_code == 429:
        pass_check(
            "31st authentication request is rate limited"
        )
    else:
        fail_check(
            "31st authentication request",
            (
                f"expected HTTP 429 after 30 requests, "
                f"got HTTP {response.status_code}"
            )
        )

    # ============================================================
    # 4. RETRY-AFTER
    # ============================================================

    print()
    print("[4] RETRY-AFTER")

    if (
        response.status_code == 429
        and response.headers.get("Retry-After") == "60"
    ):
        pass_check(
            "Shared rate-limit response includes Retry-After: 60"
        )
    else:
        fail_check(
            "Retry-After",
            (
                f"expected 429 + Retry-After: 60, "
                f"got HTTP {response.status_code} "
                f"with Retry-After={response.headers.get('Retry-After')!r}"
            )
        )

finally:
    clear_rate_limits()

    print()
    print("=" * 70)

    if failures == 0:
        print(
            "V0.8.29 CROSS-ENDPOINT RATE-LIMIT BYPASS TEST PASSED"
        )
    else:
        print(
            "V0.8.29 CROSS-ENDPOINT RATE-LIMIT BYPASS TEST FAILED"
        )

    print("=" * 70)

raise SystemExit(1 if failures else 0)
