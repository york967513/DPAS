import os
import secrets
import shutil
from pathlib import Path

import app.client_storage as client_storage
from app.client_storage import (
    CLIENT_DATA_PATH,
    save_private_key,
    load_private_key,
)


RUN_ID = secrets.token_hex(4)

READ_USERNAME = f"V0836_READ_{RUN_ID}"
WRITE_USERNAME = f"V0836_WRITE_{RUN_ID}"
NORMAL_USERNAME = f"V0836_NORMAL_{RUN_ID}"

READ_FILE = CLIENT_DATA_PATH / f"{READ_USERNAME}.key"
WRITE_FILE = CLIENT_DATA_PATH / f"{WRITE_USERNAME}.key"
NORMAL_FILE = CLIENT_DATA_PATH / f"{NORMAL_USERNAME}.key"

OUTSIDE_DIR = CLIENT_DATA_PATH.parent / f"V0836_OUTSIDE_{RUN_ID}"

READ_OUTSIDE = OUTSIDE_DIR / "read_target.key"
WRITE_OUTSIDE = OUTSIDE_DIR / "write_target.key"

READ_MARKER = f"V0836_READ_OUTSIDE_{RUN_ID}".encode()
WRITE_INITIAL = f"V0836_WRITE_INITIAL_{RUN_ID}".encode()
WRITE_ATTACK = f"V0836_WRITE_ATTACK_{RUN_ID}".encode()
NORMAL_MARKER = f"V0836_NORMAL_{RUN_ID}".encode()

failures = 0

read_state = {
    "validator_triggered": False,
    "replacement_succeeded": False,
    "replacement_blocked": False,
}

write_state = {
    "validator_triggered": False,
    "replacement_succeeded": False,
    "replacement_blocked": False,
}


def passed(label):
    print(f"[PASS] {label}")


def failed(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def cleanup():
    for path in (
        READ_FILE,
        WRITE_FILE,
        NORMAL_FILE,
    ):
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


def replace_with_symlink(
    original_path,
    target_path,
    state,
    label
):
    try:
        original_path.unlink()

        os.symlink(
            str(target_path.resolve()),
            str(original_path),
            target_is_directory=False
        )

        state["replacement_succeeded"] = True

        print(
            f"  [ATTACK] {label} pathname replaced with external symlink"
        )

    except PermissionError as exc:
        if getattr(exc, "winerror", None) == 32:
            state["replacement_blocked"] = True

            print(
                f"  [ATTACK BLOCKED] {label} pathname replacement rejected "
                "by the open file handle (WinError 32)"
            )
        else:
            raise


print("=" * 72)
print("DPAS V0.8.36 TOCTOU FILE REPLACEMENT SECURITY TEST")
print("=" * 72)

original_validator = (
    client_storage._validate_open_private_key
)

try:
    CLIENT_DATA_PATH.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTSIDE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    READ_FILE.write_bytes(
        b"SAFE_READ_FILE"
    )

    WRITE_FILE.write_bytes(
        WRITE_INITIAL
    )

    NORMAL_FILE.write_bytes(
        NORMAL_MARKER
    )

    READ_OUTSIDE.write_bytes(
        READ_MARKER
    )

    WRITE_OUTSIDE.write_bytes(
        WRITE_INITIAL
    )

    print()
    print("[1] PREPARE TEST FILES")
    print()
    print("WHAT WE CHECK:")
    print("Creates safe files and attacker-controlled targets.")

    if (
        READ_FILE.exists()
        and WRITE_FILE.exists()
        and NORMAL_FILE.exists()
        and READ_OUTSIDE.exists()
        and WRITE_OUTSIDE.exists()
    ):
        passed(
            "Temporary test files created"
        )
    else:
        failed(
            "Temporary test files",
            "one or more required files are missing"
        )

    print()
    print("[2] TOCTOU READ ATTACK")
    print()
    print("ATTACK MODEL:")
    print("DPAS opens and validates the file object.")
    print("The attacker immediately attempts to replace the pathname.")
    print("DPAS then reads using the already-opened descriptor.")
    print()
    print("SAFE OUTCOMES:")
    print("A. Windows blocks pathname replacement because the file is open.")
    print("B. Replacement succeeds, but DPAS still reads from the original descriptor.")

    def malicious_read_validator(
        file_descriptor,
        client_root
    ):
        original_validator(
            file_descriptor,
            client_root
        )

        read_state["validator_triggered"] = True

        replace_with_symlink(
            READ_FILE,
            READ_OUTSIDE,
            read_state,
            "READ"
        )

    client_storage._validate_open_private_key = (
        malicious_read_validator
    )

    try:
        read_result = load_private_key(
            READ_USERNAME
        )

        print(
            f"  Result returned by load_private_key(): {read_result!r}"
        )

        if read_result == b"SAFE_READ_FILE":
            if read_state["replacement_blocked"]:
                passed(
                    "TOCTOU read protected by open-handle sharing rules"
                )
            elif read_state["replacement_succeeded"]:
                passed(
                    "TOCTOU read remained bound to the original file descriptor"
                )
            else:
                failed(
                    "TOCTOU read protection",
                    "read returned safe data but the attack state is unknown"
                )

        elif read_result == READ_MARKER:
            failed(
                "TOCTOU read protection",
                "external target was read after validation"
            )

        else:
            failed(
                "TOCTOU read protection",
                f"unexpected returned data: {read_result!r}"
            )

    except Exception as exc:
        failed(
            "TOCTOU read protection",
            f"unexpected exception: {type(exc).__name__}: {exc}"
        )

    if read_state["validator_triggered"]:
        passed(
            "Read validation hook executed"
        )
    else:
        failed(
            "Read attack execution",
            "validation hook was not triggered"
        )

    client_storage._validate_open_private_key = (
        original_validator
    )

    print()
    print("[3] TOCTOU WRITE ATTACK")
    print()
    print("ATTACK MODEL:")
    print("DPAS opens and validates the file object.")
    print("The attacker immediately attempts to replace the pathname.")
    print("DPAS then writes using the already-opened descriptor.")
    print()
    print("SAFE OUTCOMES:")
    print("A. Windows blocks pathname replacement.")
    print("B. Replacement succeeds, but write remains bound to the original descriptor.")

    def malicious_write_validator(
        file_descriptor,
        client_root
    ):
        original_validator(
            file_descriptor,
            client_root
        )

        write_state["validator_triggered"] = True

        replace_with_symlink(
            WRITE_FILE,
            WRITE_OUTSIDE,
            write_state,
            "WRITE"
        )

    client_storage._validate_open_private_key = (
        malicious_write_validator
    )

    try:
        save_private_key(
            WRITE_USERNAME,
            WRITE_ATTACK
        )

        outside_data = WRITE_OUTSIDE.read_bytes()

        print(
            f"  External target after save_private_key(): {outside_data!r}"
        )

        if outside_data == WRITE_INITIAL:
            if write_state["replacement_blocked"]:
                passed(
                    "TOCTOU write protected by open-handle sharing rules"
                )
            elif write_state["replacement_succeeded"]:
                passed(
                    "TOCTOU write remained bound to the original file descriptor"
                )
            else:
                failed(
                    "TOCTOU write protection",
                    "external target remained unchanged but attack state is unknown"
                )

        elif outside_data == WRITE_ATTACK:
            failed(
                "TOCTOU write protection",
                "external target was modified after validation"
            )

        else:
            failed(
                "TOCTOU write protection",
                f"unexpected external target data: {outside_data!r}"
            )

    except Exception as exc:
        failed(
            "TOCTOU write protection",
            f"unexpected exception: {type(exc).__name__}: {exc}"
        )

    if write_state["validator_triggered"]:
        passed(
            "Write validation hook executed"
        )
    else:
        failed(
            "Write attack execution",
            "validation hook was not triggered"
        )

    client_storage._validate_open_private_key = (
        original_validator
    )

    print()
    print("[4] OUTSIDE TARGET INTEGRITY")
    print()

    if READ_OUTSIDE.read_bytes() == READ_MARKER:
        passed(
            "External read target remained unchanged"
        )
    else:
        failed(
            "External read target integrity",
            "external read target was modified"
        )

    if WRITE_OUTSIDE.read_bytes() == WRITE_INITIAL:
        passed(
            "External write target remained unchanged"
        )
    else:
        failed(
            "External write target integrity",
            f"unexpected data: {WRITE_OUTSIDE.read_bytes()!r}"
        )

    print()
    print("[5] NORMAL STORAGE REGRESSION")
    print()
    print("WHAT WE CHECK:")
    print("Confirms ordinary private-key storage remains functional.")

    client_storage._validate_open_private_key = (
        original_validator
    )

    save_private_key(
        NORMAL_USERNAME,
        NORMAL_MARKER
    )

    if (
        NORMAL_FILE.exists()
        and NORMAL_FILE.is_file()
        and NORMAL_FILE.read_bytes() == NORMAL_MARKER
    ):
        passed(
            "Normal private-key write still works"
        )
    else:
        failed(
            "Normal private-key write",
            "normal file was not created correctly"
        )

    if load_private_key(
        NORMAL_USERNAME
    ) == NORMAL_MARKER:
        passed(
            "Normal private-key read still works"
        )
    else:
        failed(
            "Normal private-key read",
            "normal marker was not returned"
        )

    print()
    print("[6] FINAL RESULT")
    print()

    if failures == 0:
        print(
            "[PASS] V0.8.36 TOCTOU SECURITY TEST PASSED"
        )
    else:
        print(
            f"[FAIL] V0.8.36 SECURITY TEST FOUND {failures} ISSUE(S)"
        )

finally:
    client_storage._validate_open_private_key = (
        original_validator
    )

    cleanup()

    print()
    print("[7] CLEANUP")

    if not (
        READ_FILE.exists()
        or READ_FILE.is_symlink()
        or WRITE_FILE.exists()
        or WRITE_FILE.is_symlink()
        or NORMAL_FILE.exists()
        or NORMAL_FILE.is_symlink()
        or OUTSIDE_DIR.exists()
    ):
        passed(
            "All temporary TOCTOU objects removed"
        )
    else:
        failed(
            "TOCTOU cleanup",
            "temporary objects remain"
        )

print()
print("=" * 72)

raise SystemExit(
    1 if failures else 0
)