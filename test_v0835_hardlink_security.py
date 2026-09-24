import os
import secrets
import shutil
from pathlib import Path

from app.client_storage import (
    CLIENT_DATA_PATH,
    save_private_key,
    load_private_key,
)


RUN_ID = secrets.token_hex(4)

HARDLINK_USERNAME = f"V0835_LINK_{RUN_ID}"
HARDLINK_FILE = CLIENT_DATA_PATH / f"{HARDLINK_USERNAME}.key"

OUTSIDE_DIR = CLIENT_DATA_PATH.parent / f"V0835_OUTSIDE_{RUN_ID}"
OUTSIDE_FILE = OUTSIDE_DIR / "outside.key"

INITIAL_MARKER = f"V0835_INITIAL_{RUN_ID}".encode()
ATTACK_MARKER = f"V0835_ATTACK_{RUN_ID}".encode()

NORMAL_USERNAME = f"V0835_NORMAL_{RUN_ID}"
NORMAL_FILE = CLIENT_DATA_PATH / f"{NORMAL_USERNAME}.key"
NORMAL_MARKER = f"V0835_NORMAL_{RUN_ID}".encode()

failures = 0


def passed(label):
    print(f"[PASS] {label}")


def failed(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def cleanup():
    for path in (HARDLINK_FILE, NORMAL_FILE):
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass

    try:
        if OUTSIDE_DIR.exists():
            shutil.rmtree(OUTSIDE_DIR)
    except OSError:
        pass


print("=" * 72)
print("DPAS V0.8.35 HARD LINK / FILE ALIAS SECURITY TEST")
print("=" * 72)

try:
    CLIENT_DATA_PATH.mkdir(parents=True, exist_ok=True)
    OUTSIDE_DIR.mkdir(parents=True, exist_ok=True)

    OUTSIDE_FILE.write_bytes(INITIAL_MARKER)

    print()
    print("[1] PREPARE OUTSIDE TARGET")
    print()
    print("WHAT WE CHECK:")
    print("Creates a temporary target file outside client_keys.")
    print()
    print("ATTACK MODEL:")
    print("The attacker creates another filename inside client_keys")
    print("that references the same underlying file.")
    print()
    print(f"  Outside target: {OUTSIDE_FILE.resolve()}")

    if OUTSIDE_FILE.read_bytes() == INITIAL_MARKER:
        passed("Outside target created correctly")
    else:
        failed(
            "Outside target creation",
            "initial marker is incorrect"
        )

    print()
    print("[2] CREATE HARD LINK")
    print()
    print("WHAT WE CHECK:")
    print("Creates a hard link inside client_keys to the outside target.")
    print()
    print("IMPORTANT:")
    print("Unlike a symbolic link, the hard link does not resolve to another path.")
    print("Both names reference the same file data.")

    try:
        os.link(
            str(OUTSIDE_FILE.resolve()),
            str(HARDLINK_FILE)
        )
    except (OSError, NotImplementedError) as exc:
        print()
        print(
            f"[ENVIRONMENT ERROR] Hard-link creation failed: "
            f"{type(exc).__name__}: {exc}"
        )
        print()
        print("The security test could not be executed.")
        raise SystemExit(2)

    if HARDLINK_FILE.exists() and HARDLINK_FILE.is_file():
        passed("Hard link created")
    else:
        failed(
            "Hard-link creation",
            "expected hard-link file does not exist"
        )

    print()
    print(f"  Hard-link path: {HARDLINK_FILE.resolve()}")
    print(f"  Outside path:   {OUTSIDE_FILE.resolve()}")

    print()
    print("[3] HARD LINK READ ESCAPE")
    print()
    print("WHAT WE CHECK:")
    print("Attempts to read the outside target through the normal DPAS")
    print("username-derived .key path.")
    print()
    print("EXPECTED SECURITY BEHAVIOR:")
    print("DPAS must not return the contents of the outside target.")

    try:
        result = load_private_key(HARDLINK_USERNAME)

        if result == INITIAL_MARKER:
            failed(
                "Hard-link read escape was blocked",
                "load_private_key() returned the exact contents of the outside target"
            )
        elif result is None:
            passed("Hard-link read escape was blocked")
        else:
            failed(
                "Hard-link read escape was blocked",
                f"load_private_key() returned unexpected data: {result!r}"
            )

    except ValueError as exc:
        print(f"  Exception: ValueError: {exc}")
        passed("Hard-link read escape was blocked")

    except OSError as exc:
        failed(
            "Hard-link read escape was blocked",
            f"unexpected filesystem error: {exc}"
        )

    print()
    print("[4] HARD LINK WRITE ESCAPE")
    print()
    print("WHAT WE CHECK:")
    print("Attempts to modify the outside target through the hard-linked .key path.")
    print()
    print("EXPECTED SECURITY BEHAVIOR:")
    print("DPAS must reject the path before writing to the external file.")

    try:
        save_private_key(
            HARDLINK_USERNAME,
            ATTACK_MARKER
        )

        current_data = OUTSIDE_FILE.read_bytes()

        if current_data == ATTACK_MARKER:
            failed(
                "Hard-link write escape was blocked",
                "save_private_key() modified the outside target through the hard link"
            )
        else:
            failed(
                "Hard-link write escape was blocked",
                f"save_private_key() completed unexpectedly; outside target now contains {current_data!r}"
            )

    except ValueError as exc:
        print(f"  Exception: ValueError: {exc}")
        passed("Hard-link write escape was blocked")

    except OSError as exc:
        failed(
            "Hard-link write escape was blocked",
            f"unexpected filesystem error: {exc}"
        )

    print()
    print("[5] OUTSIDE TARGET INTEGRITY")
    print()
    print("WHAT WE CHECK:")
    print("Confirms whether the outside target was changed.")

    current_data = OUTSIDE_FILE.read_bytes()

    if current_data == INITIAL_MARKER:
        passed("Outside target remained unchanged")
    elif current_data == ATTACK_MARKER:
        failed(
            "Outside target integrity",
            "outside target contains the attack marker"
        )
    else:
        failed(
            "Outside target integrity",
            f"unexpected outside target contents: {current_data!r}"
        )

    print()
    print("[6] RESTORE TEST TARGET")
    print()
    print("The outside target is test-only data.")
    print("Restore its original marker before cleanup so the test leaves")
    print("no modified data behind.")

    OUTSIDE_FILE.write_bytes(INITIAL_MARKER)

    if OUTSIDE_FILE.read_bytes() == INITIAL_MARKER:
        passed("Outside test target restored")
    else:
        failed(
            "Outside test target restoration",
            "could not restore original marker"
        )

    print()
    print("[7] NORMAL STORAGE REGRESSION")
    print()
    print("WHAT WE CHECK:")
    print("Confirms that ordinary private-key storage still works.")

    save_private_key(
        NORMAL_USERNAME,
        NORMAL_MARKER
    )

    if (
        NORMAL_FILE.exists()
        and NORMAL_FILE.is_file()
        and NORMAL_FILE.read_bytes() == NORMAL_MARKER
    ):
        passed("Normal private-key write still works")
    else:
        failed(
            "Normal private-key write",
            "normal key file was not created correctly"
        )

    if load_private_key(NORMAL_USERNAME) == NORMAL_MARKER:
        passed("Normal private-key read still works")
    else:
        failed(
            "Normal private-key read",
            "normal marker was not returned"
        )

    print()
    print("[8] FINAL RESULT")
    print()

    if failures == 0:
        print("[PASS] V0.8.35 HARD LINK / FILE ALIAS SECURITY TEST PASSED")
    else:
        print(f"[FAIL] V0.8.35 SECURITY TEST FOUND {failures} ISSUE(S)")

finally:
    cleanup()

    print()
    print("[9] CLEANUP")

    if not HARDLINK_FILE.exists():
        passed("Temporary hard link removed")
    else:
        failed(
            "Hard-link cleanup",
            f"hard link still exists: {HARDLINK_FILE}"
        )

    if not NORMAL_FILE.exists():
        passed("Temporary normal file removed")
    else:
        failed(
            "Normal-file cleanup",
            f"normal temporary file still exists: {NORMAL_FILE}"
        )

    if not OUTSIDE_DIR.exists():
        passed("Temporary outside directory removed")
    else:
        failed(
            "Outside-directory cleanup",
            f"directory still exists: {OUTSIDE_DIR}"
        )

print()
print("=" * 72)

raise SystemExit(1 if failures else 0)

