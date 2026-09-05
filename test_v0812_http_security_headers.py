from fastapi.testclient import TestClient

from app.api import app


EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
}


print("=" * 70)
print("DPAS V0.8.12 HTTP SECURITY HEADERS / API HARDENING TEST")
print("=" * 70)

client = TestClient(app)

failures = 0


def check_headers(label, response):
    global failures

    print()
    print(label)
    print(f"HTTP {response.status_code}")

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    for header_name, expected_value in EXPECTED_HEADERS.items():

        actual_value = headers.get(header_name)

        if actual_value == expected_value:
            print(
                f"[PASS] {header_name}: {actual_value}"
            )
        else:
            print(
                f"[FAIL] {header_name}: "
                f"expected '{expected_value}', "
                f"got '{actual_value}'"
            )
            failures += 1


# ============================================================
# 1. PUBLIC SUCCESS RESPONSE
# ============================================================

response = client.get("/health")

check_headers(
    "[1] PUBLIC SUCCESS RESPONSE",
    response
)

if response.status_code == 200:
    print("[PASS] /health returned HTTP 200")
else:
    print(
        f"[FAIL] /health returned HTTP {response.status_code}"
    )
    failures += 1


# ============================================================
# 2. UNAUTHENTICATED PROTECTED RESPONSE
# ============================================================

response = client.get("/session")

check_headers(
    "[2] UNAUTHENTICATED PROTECTED RESPONSE",
    response
)

if response.status_code == 401:
    print("[PASS] /session rejected without authentication")
else:
    print(
        f"[FAIL] /session returned HTTP "
        f"{response.status_code}"
    )
    failures += 1


# ============================================================
# 3. NOT FOUND RESPONSE
# ============================================================

response = client.get("/this-endpoint-does-not-exist")

check_headers(
    "[3] NOT FOUND RESPONSE",
    response
)

if response.status_code == 404:
    print("[PASS] Unknown endpoint returned HTTP 404")
else:
    print(
        f"[FAIL] Unknown endpoint returned HTTP "
        f"{response.status_code}"
    )
    failures += 1


# ============================================================
# 4. SECURITY HEADERS MUST NOT BE WEAKENED
# ============================================================

print()
print("[4] SECURITY HEADER VALUE HARDENING")

weak_values = {
    "x-content-type-options": {
        "Content-Type-Options",
        "allow",
        "sniff",
    },
    "x-frame-options": {
        "ALLOWALL",
        "ALLOW-FROM",
    },
    "referrer-policy": {
        "unsafe-url",
    },
}

for header_name, forbidden_values in weak_values.items():

    response = client.get("/health")

    actual_value = response.headers.get(header_name)

    if actual_value not in forbidden_values:
        print(
            f"[PASS] {header_name} is not weakened: "
            f"{actual_value}"
        )
    else:
        print(
            f"[FAIL] {header_name} uses weak value: "
            f"{actual_value}"
        )
        failures += 1


# ============================================================
# 5. CONSISTENCY ACROSS RESPONSE TYPES
# ============================================================

print()
print("[5] HEADER CONSISTENCY")

health = client.get("/health")
session = client.get("/session")
missing = client.get("/this-endpoint-does-not-exist")

for header_name, expected_value in EXPECTED_HEADERS.items():

    values = [
        health.headers.get(header_name),
        session.headers.get(header_name),
        missing.headers.get(header_name),
    ]

    if all(value == expected_value for value in values):
        print(
            f"[PASS] {header_name} consistent across "
            f"200 / 401 / 404 responses"
        )
    else:
        print(
            f"[FAIL] {header_name} inconsistent: {values}"
        )
        failures += 1


# ============================================================
# 6. NO UNEXPECTED SECURITY-HOSTILE VALUES
# ============================================================

print()
print("[6] HOSTILE HEADER VALUE CHECK")

response = client.get("/health")

hostile_fragments = [
    "unsafe-inline",
    "unsafe-eval",
    "*",
    "ALLOWALL",
]

for header_name in EXPECTED_HEADERS:

    actual_value = response.headers.get(header_name, "")

    found = [
        fragment
        for fragment in hostile_fragments
        if fragment.lower() in actual_value.lower()
    ]

    if not found:
        print(
            f"[PASS] {header_name} contains no tested hostile directive"
        )
    else:
        print(
            f"[FAIL] {header_name} contains hostile directive(s): "
            f"{found}"
        )
        failures += 1


# ============================================================
# FINAL RESULT
# ============================================================

print()
print("=" * 70)

if failures == 0:
    print("V0.8.12 HTTP SECURITY HEADERS TEST PASSED")
else:
    print(
        f"V0.8.12 HTTP SECURITY HEADERS TEST FAILED: "
        f"{failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
