import hashlib
from app.session_manager import (
    create_user_session,
    validate_session,
    get_session_username,
    logout,
    _hash_token,
)
from app.database import get_connection


USER_A = "V089TokenA"
USER_B = "V089TokenB"


def cleanup():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM sessions WHERE username IN (?, ?)",
        (USER_A, USER_B)
    )

    cursor.execute(
        "DELETE FROM audit_log WHERE username IN (?, ?)",
        (USER_A, USER_B)
    )

    connection.commit()
    connection.close()


print("=" * 70)
print("DPAS V0.8.9 TOKEN SECURITY / SESSION ISOLATION TEST")
print("=" * 70)

cleanup()

failures = 0

print()
print("[1] CREATE TWO INDEPENDENT SESSIONS")

token_a = create_user_session(USER_A)
token_b = create_user_session(USER_B)

if token_a and token_b:
    print("[PASS] Both sessions created")
else:
    print("[FAIL] Session creation failed")
    failures += 1

if token_a != token_b:
    print("[PASS] Session tokens are different")
else:
    print("[FAIL] Two users received identical tokens")
    failures += 1

print()
print("[2] TOKEN A -> USER A")

if validate_session(token_a):
    print("[PASS] Token A is valid")
else:
    print("[FAIL] Token A is not valid")
    failures += 1

username_a = get_session_username(token_a)

if username_a == USER_A:
    print("[PASS] Token A resolves only to User A")
else:
    print("[FAIL] Token A identity mismatch:", username_a)
    failures += 1

print()
print("[3] TOKEN B -> USER B")

if validate_session(token_b):
    print("[PASS] Token B is valid")
else:
    print("[FAIL] Token B is not valid")
    failures += 1

username_b = get_session_username(token_b)

if username_b == USER_B:
    print("[PASS] Token B resolves only to User B")
else:
    print("[FAIL] Token B identity mismatch:", username_b)
    failures += 1

print()
print("[4] SESSION ISOLATION")

if username_a != USER_B and username_b != USER_A:
    print("[PASS] Sessions are isolated between users")
else:
    print("[FAIL] Cross-user session identity detected")
    failures += 1

print()
print("[5] TOKEN TAMPERING")

tampered_token = token_a[:-1] + (
    "A" if token_a[-1] != "A" else "B"
)

if not validate_session(tampered_token):
    print("[PASS] Modified token rejected")
else:
    print("[FAIL] Modified token accepted")
    failures += 1

if get_session_username(tampered_token) is None:
    print("[PASS] Modified token cannot resolve a username")
else:
    print("[FAIL] Modified token resolved a username")
    failures += 1

print()
print("[6] RAW TOKEN STORAGE CHECK")

connection = get_connection()
cursor = connection.cursor()

cursor.execute(
    """
    SELECT token_hash
    FROM sessions
    WHERE username IN (?, ?)
    """,
    (USER_A, USER_B)
)

rows = cursor.fetchall()

raw_token_found = False

for row in rows:
    stored_value = row[0]

    if isinstance(stored_value, bytes):
        stored_text = stored_value.hex()
    else:
        stored_text = str(stored_value)

    if token_a in stored_text or token_b in stored_text:
        raw_token_found = True

connection.close()

if not raw_token_found:
    print("[PASS] Raw session tokens are not stored in the database")
else:
    print("[FAIL] Raw session token found in database")
    failures += 1

print()
print("[7] SHA-256 HASH VERIFICATION")

expected_hash_a = _hash_token(token_a)
expected_hash_b = _hash_token(token_b)

connection = get_connection()
cursor = connection.cursor()

cursor.execute(
    """
    SELECT username, token_hash
    FROM sessions
    WHERE username IN (?, ?)
    ORDER BY username
    """,
    (USER_A, USER_B)
)

rows = cursor.fetchall()
connection.close()

hash_a_ok = False
hash_b_ok = False

for username, stored_hash in rows:

    if username == USER_A and stored_hash == expected_hash_a:
        hash_a_ok = True

    if username == USER_B and stored_hash == expected_hash_b:
        hash_b_ok = True

if hash_a_ok:
    print("[PASS] User A token hash matches SHA-256(token A)")
else:
    print("[FAIL] User A token hash mismatch")
    failures += 1

if hash_b_ok:
    print("[PASS] User B token hash matches SHA-256(token B)")
else:
    print("[FAIL] User B token hash mismatch")
    failures += 1

print()
print("[8] AUDIT LOG TOKEN EXPOSURE CHECK")

connection = get_connection()
cursor = connection.cursor()

cursor.execute(
    """
    SELECT action, details
    FROM audit_log
    WHERE username IN (?, ?)
    """,
    (USER_A, USER_B)
)

audit_rows = cursor.fetchall()
connection.close()

raw_token_in_audit = False

for action, details in audit_rows:

    text = f"{action} {details}"

    if token_a in text or token_b in text:
        raw_token_in_audit = True
        break

if not raw_token_in_audit:
    print("[PASS] Raw session tokens are absent from audit log")
else:
    print("[FAIL] Raw session token found in audit log")
    failures += 1

print()
print("[9] LOGOUT / REVOCATION")

if logout(token_a):
    print("[PASS] User A session revoked")
else:
    print("[FAIL] User A session revocation failed")
    failures += 1

if not validate_session(token_a):
    print("[PASS] Revoked token A rejected")
else:
    print("[FAIL] Revoked token A still accepted")
    failures += 1

if get_session_username(token_a) is None:
    print("[PASS] Revoked token A cannot resolve username")
else:
    print("[FAIL] Revoked token A still resolves username")
    failures += 1

print()
print("[10] USER B SESSION AFTER USER A REVOCATION")

if validate_session(token_b):
    print("[PASS] User B session remains valid")
else:
    print("[FAIL] User B session was affected by User A revocation")
    failures += 1

if get_session_username(token_b) == USER_B:
    print("[PASS] User B identity remains isolated")
else:
    print("[FAIL] User B identity changed unexpectedly")
    failures += 1

print()
print("[CLEANUP] Removing V0.8.9 test sessions and audit records")

cleanup()

print()
print("=" * 70)

if failures == 0:
    print("V0.8.9 TOKEN SECURITY TEST PASSED")
else:
    print(f"V0.8.9 TOKEN SECURITY TEST FAILED: {failures} failure(s)")

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
