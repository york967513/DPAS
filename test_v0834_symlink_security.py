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

LINK_USERNAME = f"V0834_LINK_{RUN_ID}"
LINK_FILE = CLIENT_DATA_PATH / f"{LINK_USERNAME}.key"

OUTSIDE_DIR = CLIENT_DATA_PATH.parent / f"V0834_OUTSIDE_{RUN_ID}"
OUTSIDE_FILE = OUTSIDE_DIR / "outside.key"

INITIAL_MARKER = f"V0834_INITIAL_{RUN_ID}".encode()
ATTACK_MARKER = f"V0834_ATTACK_{RUN_ID}".encode()

NORMAL_USERNAME = f"V0834_NORMAL_{RUN_ID}"
NORMAL_FILE = CLIENT_DATA_PATH / f"{NORMAL_USERNAME}.key"
NORMAL_MARKER = f"V0834_NORMAL_{RUN_ID}".encode()

failures = 0


def passed(label):
    print(f"[PASS] {label}")


def failed(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def cleanup():
    for path in (LINK_FILE, NORMAL_FILE):
        try:
            if path.is_symlink() or path.exists():
                path.unlink()
        except OSError:
            pass

    try:
        if OUTSIDE_DIR.exists():
            shutil.rmtree(OUTSIDE_DIR)
    except OSError:
        pass


print("=" * 72)
print("DPAS V0.8.34 SYMLINK / REPARSE-POINT SECURITY TEST")
print("=" * 72)

try:
    CLIENT_DATA_PATH.mkdir(parents=True, exist_ok=True)
    OUTSIDE_DIR.mkdir(parents=True, exist_ok=True)
    OUTSIDE_FILE.write_bytes(INITIAL_MARKER)

    print()
    print("[1] OUTSIDE TARGET")
    print(f"  Target: {OUTSIDE_FILE.resolve()}")

    if OUTSIDE_FILE.read_bytes() == INITIAL_MARKER:
        passed("Outside target created correctly")
    else:
        failed(
            "Outside target creation",
            "marker content is incorrect"
        )

    print()
    print("[2] CREATE SYMBOLIC LINK")

    absolute_target = OUTSIDE_FILE.resolve()

    try:
        os.symlink(
            str(absolute_target),
            str(LINK_FILE),
            target_is_directory=False
        )
    except (OSError, NotImplementedError) as exc:
        print(
            f"[ENVIRONMENT ERROR] Symbolic-link creation failed: "
            f"{type(exc).__name__}: {exc}"
        )
        print("The security test could not be executed.")
        raise SystemExit(2)

    if LINK_FILE.is_symlink():
        passed("Symbolic link created")
    else:
        failed(
            "Symbolic link creation",
            "link does not exist as a symbolic link"
        )

    if LINK_FILE.resolve() == absolute_target:
        passed("Symbolic link resolves to the intended outside target")
    else:
        failed(
            "Symbolic link target",
            f"unexpected resolved path: {LINK_FILE.resolve()}"
        )

    print()
    print("[3] SYMLINK READ ESCAPE")

    try:
        result = load_private_key(LINK_USERNAME)
        failed(
            "Read escape blocked",
            f"load_private_key() returned {result!r}"
        )
    except ValueError as exc:
        print(f"  Exception: ValueError: {exc}")
        passed("Read escape blocked")
    except OSError as exc:
        failed(
            "Read escape blocked",
            f"unexpected OSError: {exc}"
        )

    print()
    print("[4] SYMLINK WRITE ESCAPE")

    try:
        save_private_key(
            LINK_USERNAME,
            ATTACK_MARKER
        )
        failed(
            "Write escape blocked",
            "save_private_key() unexpectedly completed"
        )
    except ValueError as exc:
        print(f"  Exception: ValueError: {exc}")
        passed("Write escape blocked")
    except OSError as exc:
        failed(
            "Write escape blocked",
            f"unexpected OSError: {exc}"
        )

    print()
    print("[5] OUTSIDE TARGET INTEGRITY")

    if OUTSIDE_FILE.read_bytes() == INITIAL_MARKER:
        passed("Outside target remained unchanged")
    else:
        failed(
            "Outside target integrity",
            "external target was modified"
        )

    print()
    print("[6] NORMAL STORAGE REGRESSION")

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
            "normal file was not created correctly"
        )

    if load_private_key(NORMAL_USERNAME) == NORMAL_MARKER:
        passed("Normal private-key read still works")
    else:
        failed(
            "Normal private-key read",
            "normal marker was not returned"
        )

    print()
    print("[7] FINAL RESULT")

    if failures == 0:
        print("[PASS] V0.8.34 SYMLINK / REPARSE-POINT SECURITY TEST PASSED")
    else:
        print(f"[FAIL] V0.8.34 FOUND {failures} ISSUE(S)")

finally:
    cleanup()

    print()
    print("[8] CLEANUP")

    if not LINK_FILE.exists() and not LINK_FILE.is_symlink():
        passed("Temporary symbolic link removed")
    else:
        failed(
            "Symbolic link cleanup",
            f"link still exists: {LINK_FILE}"
        )

    if not OUTSIDE_DIR.exists():
        passed("Temporary outside directory removed")
    else:
        failed(
            "Outside directory cleanup",
            f"directory still exists: {OUTSIDE_DIR}"
        )

print()
print("=" * 72)

raise SystemExit(1 if failures else 0)

