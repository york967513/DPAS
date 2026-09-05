import secrets
import unicodedata

from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import delete_user, get_user
from app.session_manager import create_user_session, logout


RUN_ID = secrets.token_hex(4)

PASSWORD = "DPAS_Test_Password_2026!"

ASCII_USER = f"V0827Admin_{RUN_ID}"
CYRILLIC_USER = f"V0827Аdmin_{RUN_ID}"
ZERO_WIDTH_USER = f"V0827Admin\u200b_{RUN_ID}"
FULLWIDTH_USER = f"V0827Ａdmin_{RUN_ID}"

NFC_USER = f"V0827é_{RUN_ID}"
NFD_USER = f"V0827e\u0301_{RUN_ID}"

LOWER_USER = f"V0827admin_{RUN_ID}"
UPPER_USER = f"V0827ADMIN_{RUN_ID}"

TEST_USERS = [
    ASCII_USER,
    CYRILLIC_USER,
    ZERO_WIDTH_USER,
    FULLWIDTH_USER,
    NFC_USER,
    NFD_USER,
    LOWER_USER,
    UPPER_USER,
]

client = TestClient(app)

failures = 0
tokens = []


def cleanup():
    for token in tokens:
        try:
            logout(token)
        except Exception:
            pass

    for username in TEST_USERS:
        try:
            delete_user(username)
        except Exception:
            pass


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def expect_status(label, response, expected):
    if response.status_code == expected:
        pass_check(
            f"{label} -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            label,
            f"expected HTTP {expected}, got HTTP {response.status_code}"
        )


def expect_status_family(label, response, allowed):
    if response.status_code in allowed:
        pass_check(
            f"{label} -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            label,
            f"expected one of {sorted(allowed)}, got HTTP {response.status_code}"
        )


def printable(value):
    codepoints = " ".join(
        f"U+{ord(char):04X}"
        for char in value
    )

    return f"{value!r} [{codepoints}]"


def check_identity(label, response, expected_username):
    if response.status_code != 200:
        fail_check(
            label,
            f"expected HTTP 200, got HTTP {response.status_code}"
        )
        return

    body = response.json()

    if body.get("username") == expected_username:
        pass_check(
            f"{label}: identity preserved exactly"
        )
    else:
        fail_check(
            label,
            f"expected {expected_username!r}, got {body.get('username')!r}"
        )


try:

    print("=" * 70)
    print("DPAS V0.8.27 UNICODE NORMALIZATION / CONFUSABLE IDENTITY TEST")
    print("=" * 70)

    print()
    print(f"[SETUP] Unique test namespace: {RUN_ID}")

    cleanup()

    print()
    print("[SETUP] Test identities:")

    for username in TEST_USERS:
        print(f"  - {printable(username)}")


    # ============================================================
    # 1. BASELINE ASCII USERNAME
    # ============================================================

    print()
    print("[1] BASELINE ASCII USERNAME")

    result = register_user(
        ASCII_USER,
        PASSWORD
    )

    if result is not None:
        pass_check(
            "ASCII username registered"
        )
    else:
        fail_check(
            "ASCII username registration",
            "registration returned None"
        )


    # ============================================================
    # 2. CYRILLIC LOOKALIKE
    # ============================================================

    print()
    print("[2] CYRILLIC LOOKALIKE")

    print(
        f"Latin:    {printable(ASCII_USER)}"
    )

    print(
        f"Cyrillic: {printable(CYRILLIC_USER)}"
    )

    result = register_user(
        CYRILLIC_USER,
        PASSWORD
    )

    if result is not None:
        pass_check(
            "Cyrillic-lookalike username registered separately"
        )
    else:
        fail_check(
            "Cyrillic-lookalike registration",
            "registration returned None"
        )

    ascii_db = get_user(
        ASCII_USER
    )

    cyrillic_db = get_user(
        CYRILLIC_USER
    )

    if ascii_db is not None and cyrillic_db is not None:
        pass_check(
            "Both lookalike identities exist"
        )
    else:
        fail_check(
            "Lookalike identities",
            "one or both identities missing"
        )

    if (
        ascii_db is not None
        and cyrillic_db is not None
        and ascii_db[0] != cyrillic_db[0]
    ):
        pass_check(
            "Lookalike usernames have different database identities"
        )
    else:
        fail_check(
            "Lookalike database identity",
            "identities were not distinct"
        )


    # ============================================================
    # 3. ZERO-WIDTH CHARACTER
    # ============================================================

    print()
    print("[3] ZERO-WIDTH CHARACTER")

    result = register_user(
        ZERO_WIDTH_USER,
        PASSWORD
    )

    if result is not None:
        pass_check(
            "Zero-width username registered"
        )
    else:
        fail_check(
            "Zero-width registration",
            "registration returned None"
        )

    if get_user(ZERO_WIDTH_USER) is not None:
        pass_check(
            "Zero-width username stored distinctly"
        )
    else:
        fail_check(
            "Zero-width lookup",
            "username not found"
        )


    # ============================================================
    # 4. FULLWIDTH CHARACTER
    # ============================================================

    print()
    print("[4] FULLWIDTH CHARACTER")

    result = register_user(
        FULLWIDTH_USER,
        PASSWORD
    )

    if result is not None:
        pass_check(
            "Fullwidth username registered"
        )
    else:
        fail_check(
            "Fullwidth registration",
            "registration returned None"
        )

    if get_user(FULLWIDTH_USER) is not None:
        pass_check(
            "Fullwidth username stored distinctly"
        )
    else:
        fail_check(
            "Fullwidth lookup",
            "username not found"
        )


    # ============================================================
    # 5. NFC / NFD
    # ============================================================

    print()
    print("[5] NFC / NFD")

    nfc_form = unicodedata.normalize(
        "NFC",
        NFC_USER
    )

    nfd_form = unicodedata.normalize(
        "NFD",
        NFD_USER
    )

    print(
        f"NFC: {printable(nfc_form)}"
    )

    print(
        f"NFD: {printable(nfd_form)}"
    )

    print(
        f"NFC bytes: {nfc_form.encode('utf-8')!r}"
    )

    print(
        f"NFD bytes: {nfd_form.encode('utf-8')!r}"
    )

    normalized_nfc_form = unicodedata.normalize(
        "NFC",
        nfc_form
    )

    normalized_nfd_form = unicodedata.normalize(
        "NFC",
        nfd_form
    )

    if normalized_nfc_form == normalized_nfd_form:
        pass_check(
            "NFC-normalized NFC and NFD usernames compare equal"
        )
    else:
        fail_check(
            "NFC normalization",
            "NFC-normalized representations are not equal"
        )

    result_nfc = register_user(
        NFC_USER,
        PASSWORD
    )

    result_nfd = register_user(
        NFD_USER,
        PASSWORD
    )

    if result_nfc is not None:
        pass_check(
            "NFC username registered"
        )
    else:
        fail_check(
            "NFC registration",
            "registration returned None"
        )

    if result_nfd is not None:
        pass_check(
            "NFD username registered separately"
        )
    else:
        fail_check(
            "NFD registration",
            "registration returned None"
        )


    # ============================================================
    # 6. CASE VARIATION
    # ============================================================

    print()
    print("[6] CASE VARIATION")

    result_lower = register_user(
        LOWER_USER,
        PASSWORD
    )

    result_upper = register_user(
        UPPER_USER,
        PASSWORD
    )

    if result_lower is not None:
        pass_check(
            "Lowercase username registered"
        )
    else:
        fail_check(
            "Lowercase registration",
            "registration returned None"
        )

    if result_upper is not None:
        pass_check(
            "Uppercase username registered separately"
        )
    else:
        fail_check(
            "Uppercase registration",
            "registration returned None"
        )


    # ============================================================
    # 7. AUTHENTICATION IDENTITY
    # ============================================================

    print()
    print("[7] AUTHENTICATION IDENTITY")

    for username in [
        ASCII_USER,
        CYRILLIC_USER,
        ZERO_WIDTH_USER,
        FULLWIDTH_USER,
        NFC_USER,
        NFD_USER,
    ]:

        response = client.post(
            "/auth/challenge",
            json={
                "username": username
            }
        )

        expect_status(
            f"Challenge for {printable(username)}",
            response,
            200
        )


    # ============================================================
    # 8. LOOKALIKE SESSION IDENTITY
    # ============================================================

    print()
    print("[8] LOOKALIKE SESSION IDENTITY")

    cyrillic_token = create_user_session(
        CYRILLIC_USER
    )

    tokens.append(
        cyrillic_token
    )

    response = client.get(
        "/session",
        headers={
            "Authorization": f"Bearer {cyrillic_token}"
        }
    )

    check_identity(
        "Cyrillic-lookalike session",
        response,
        CYRILLIC_USER
    )


    # ============================================================
    # 9. NFD SESSION IDENTITY
    # ============================================================

    print()
    print("[9] NFD SESSION IDENTITY")

    nfd_token = create_user_session(
        NFD_USER
    )

    tokens.append(
        nfd_token
    )

    response = client.get(
        "/session",
        headers={
            "Authorization": f"Bearer {nfd_token}"
        }
    )

    check_identity(
        "NFD session",
        response,
        NFD_USER
    )


    # ============================================================
    # 10. LOOKALIKE MUST NOT GAIN ADMIN ACCESS
    # ============================================================

    print()
    print("[10] LOOKALIKE / AUTHORIZATION")

    response = client.get(
        "/admin/users",
        headers={
            "Authorization": f"Bearer {cyrillic_token}"
        }
    )

    expect_status(
        "Cyrillic-lookalike user -> admin endpoint",
        response,
        403
    )


    # ============================================================
    # 11. EXACT DATABASE LOOKUP
    # ============================================================

    print()
    print("[11] EXACT DATABASE LOOKUP")

    for username in TEST_USERS:

        user = get_user(
            username
        )

        if user is None:
            fail_check(
                "Database lookup",
                f"username not found: {printable(username)}"
            )
        elif user[1] == username:
            pass_check(
                f"Exact lookup preserved: {printable(username)}"
            )
        else:
            fail_check(
                "Database lookup",
                f"stored value differs for {printable(username)}"
            )


    # ============================================================
    # 12. INVALID TOKEN CONTROL
    # ============================================================

    print()
    print("[12] INVALID TOKEN CONTROL")

    response = client.get(
        "/session",
        headers={
            "Authorization": "Bearer invalid-token"
        }
    )

    expect_status(
        "Invalid session token",
        response,
        401
    )


finally:

    print()
    print("[CLEANUP] Removing Unicode test users and sessions")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.27 UNICODE NORMALIZATION / CONFUSABLE IDENTITY TEST PASSED")
else:
    print(
        f"V0.8.27 UNICODE NORMALIZATION / CONFUSABLE IDENTITY "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
