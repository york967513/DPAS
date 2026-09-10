from pathlib import Path
import secrets

from app.client_storage import (
    CLIENT_DATA_PATH,
    save_private_key,
    load_private_key,
)


RUN_ID = secrets.token_hex(4)

BASE_DIR = Path("data")
CLIENT_DIR = CLIENT_DATA_PATH

SAFE_USERNAME = f"V0832_SAFE_{RUN_ID}"
TRAVERSAL_USERNAME = f"..\\v0832_traversal_{RUN_ID}"

SAFE_FILE = (
    CLIENT_DIR / f"{SAFE_USERNAME}.key"
).resolve()

OUTSIDE_FILE = (
    BASE_DIR / f"v0832_traversal_{RUN_ID}.key"
).resolve()

MARKER = f"V0832_TRAVERSAL_MARKER_{RUN_ID}".encode()

failures = 0


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


print("=" * 72)
print("DPAS V0.8.32 PATH TRAVERSAL / FILE SYSTEM BOUNDARY TEST")
print("=" * 72)

print()
print(f"[SETUP] Test namespace: {RUN_ID}")
print(f"[SETUP] Client key directory: {CLIENT_DIR.resolve()}")
print(f"[SETUP] Traversal username: {TRAVERSAL_USERNAME}")
print(f"[SETUP] Outside marker file: {OUTSIDE_FILE}")

try:

    client_root = CLIENT_DIR.resolve()

    # ============================================================
    # 1. SECURITY BOUNDARY
    # ============================================================

    print()
    print("[1] FILE SYSTEM SECURITY BOUNDARY")
    print()
    print("  WHAT WE CHECK:")
    print("  Defines the only directory allowed for client private-key files.")
    print()
    print("  VULNERABILITY TYPE:")
    print("  Path Traversal / Directory Traversal (CWE-22).")
    print()
    print("  SECURITY REQUIREMENT:")
    print("  Username-derived file paths must remain inside data/client_keys.")
    print()
    print("  FIX BEING VERIFIED:")
    print("  client_storage resolves the candidate path and rejects paths")
    print("  that escape the client-key directory.")

    if CLIENT_DIR.exists() and CLIENT_DIR.is_dir():
        pass_check(
            "Client key directory exists"
        )
    else:
        fail_check(
            "Client key directory",
            "directory does not exist"
        )

    # ============================================================
    # 2. NORMAL FILE STORAGE
    # ============================================================

    print()
    print("[2] NORMAL USERNAME FILE STORAGE")
    print()
    print("  WHAT WE CHECK:")
    print("  Verifies that a legitimate username still creates a key file.")
    print()
    print("  VULNERABILITY TYPE:")
    print("  Functional regression control.")
    print()
    print("  SAFE RESULT:")
    print("  Normal storage succeeds and remains inside the allowed directory.")

    save_private_key(
        SAFE_USERNAME,
        MARKER
    )

    if (
        SAFE_FILE.exists()
        and client_root in SAFE_FILE.parents
        and SAFE_FILE.read_bytes() == MARKER
    ):
        pass_check(
            "Normal key storage remains inside client_keys"
        )
    else:
        fail_check(
            "Normal key storage",
            f"unexpected target or content: {SAFE_FILE}"
        )

    # ============================================================
    # 3. READ PATH TRAVERSAL
    # ============================================================

    print()
    print("[3] READ PATH TRAVERSAL")
    print()
    print("  WHAT WE CHECK:")
    print("  Attempts to escape client_keys while reading a private-key file.")
    print()
    print("  VULNERABILITY TYPE:")
    print("  Path Traversal / Local File Read (CWE-22).")
    print()
    print("  ATTACK INPUT:")
    print(f"  username = {TRAVERSAL_USERNAME}")
    print()
    print("  SAFE RESULT:")
    print("  The application must reject the path before reading the outside file.")

    OUTSIDE_FILE.write_bytes(MARKER)

    try:
        result = load_private_key(
            TRAVERSAL_USERNAME
        )

        fail_check(
            "READ path traversal protection",
            f"load_private_key unexpectedly returned: {result!r}"
        )

    except ValueError as exc:
        print(f"  Exception: {type(exc).__name__}: {exc}")
        pass_check(
            "READ traversal was rejected before file access"
        )

    if OUTSIDE_FILE.exists():
        print(
            "  Outside marker still exists for verification."
        )

    # ============================================================
    # 4. WRITE PATH TRAVERSAL
    # ============================================================

    print()
    print("[4] WRITE PATH TRAVERSAL")
    print()
    print("  WHAT WE CHECK:")
    print("  Attempts to create a file outside client_keys.")
    print()
    print("  VULNERABILITY TYPE:")
    print("  Path Traversal / Arbitrary File Write (CWE-22).")
    print()
    print("  ATTACK INPUT:")
    print(f"  username = {TRAVERSAL_USERNAME}")
    print()
    print("  SAFE RESULT:")
    print("  The application must reject the path before write_bytes().")

    OUTSIDE_FILE.unlink(
        missing_ok=True
    )

    try:
        save_private_key(
            TRAVERSAL_USERNAME,
            MARKER
        )

        fail_check(
            "WRITE path traversal protection",
            "save_private_key unexpectedly completed"
        )

    except ValueError as exc:
        print(f"  Exception: {type(exc).__name__}: {exc}")
        pass_check(
            "WRITE traversal was rejected before file creation"
        )

    if not OUTSIDE_FILE.exists():
        pass_check(
            "No outside file was created"
        )
    else:
        fail_check(
            "Outside file creation",
            f"unexpected file exists: {OUTSIDE_FILE}"
        )

    # ============================================================
    # 5. CANONICAL PATH BOUNDARY
    # ============================================================

    print()
    print("[5] CANONICAL PATH BOUNDARY")
    print()
    print("  WHAT WE CHECK:")
    print("  Confirms that ..\\ is evaluated using the canonical filesystem path.")
    print()
    print("  VULNERABILITY TYPE:")
    print("  Path canonicalization / security boundary bypass.")
    print()
    print("  WHY IT MATTERS:")
    print("  A textual path can appear to start inside the allowed directory")
    print("  while its resolved location is actually outside it.")
    print()
    print("  SAFE RESULT:")
    print("  Traversal input must not produce an accepted path outside client_keys.")

    traversal_candidate = (
        CLIENT_DIR
        / f"{TRAVERSAL_USERNAME}.key"
    ).resolve()

    print(f"  ROOT     : {client_root}")
    print(f"  CANDIDATE: {traversal_candidate}")

    if client_root not in traversal_candidate.parents:
        pass_check(
            "Traversal candidate resolves outside the root and is therefore rejectable"
        )
    else:
        fail_check(
            "Canonical path analysis",
            "traversal candidate unexpectedly remained inside client_keys"
        )

    # ============================================================
    # 6. CLEANUP
    # ============================================================

    print()
    print("[6] CLEANUP")
    print()
    print("  WHAT WE CHECK:")
    print("  Removes every temporary file created by this test.")
    print()
    print("  VULNERABILITY TYPE:")
    print("  Test isolation / filesystem hygiene.")
    print()
    print("  SAFE RESULT:")
    print("  No V0.8.32 temporary files remain.")

    for target in (
        SAFE_FILE,
        OUTSIDE_FILE,
    ):
        try:
            if target.exists() and target.is_file():
                target.unlink()
                print(f"  Removed: {target}")
        except Exception as exc:
            fail_check(
                "Cleanup failure",
                f"{target}: {type(exc).__name__}: {exc}"
            )

    if not SAFE_FILE.exists() and not OUTSIDE_FILE.exists():
        pass_check(
            "All V0.8.32 temporary files were removed"
        )
    else:
        fail_check(
            "Cleanup verification",
            "one or more temporary files remain"
        )

finally:

    print()
    print("=" * 72)

    if failures == 0:
        print("V0.8.32 RESULT: PASS")
        print("Path traversal protection is working.")
        print("Filesystem access remains confined to data/client_keys.")
    else:
        print(f"V0.8.32 RESULT: FAIL ({failures} failure(s))")
        print("Filesystem boundary protection is still incomplete.")

    print("=" * 72)
