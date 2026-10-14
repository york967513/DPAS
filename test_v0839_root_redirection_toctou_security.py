import secrets
import shutil
import sys
import tempfile
from pathlib import Path

import app.client_storage as client_storage


RUN_ID = secrets.token_hex(5)

READ_USERNAME = f"V0839Read{RUN_ID}"
WRITE_USERNAME = f"V0839Write{RUN_ID}"
NORMAL_USERNAME = f"V0839Normal{RUN_ID}"

SAFE_READ = b"V0839_SAFE_INTERNAL_READ"
SAFE_WRITE = b"V0839_SAFE_INTERNAL_WRITE"
OUTSIDE_READ = b"V0839_OUTSIDE_READ_MARKER"
OUTSIDE_WRITE = b"V0839_OUTSIDE_WRITE_MARKER"
ATTACK_WRITE = b"V0839_ATTACK_WRITE_PAYLOAD"
NORMAL_MARKER = b"V0839_NORMAL_STORAGE_OK"

original_client_data_path = client_storage.CLIENT_DATA_PATH
original_get_client_root = client_storage._get_client_root

BASE_DIR = Path(tempfile.mkdtemp(prefix="dpas_v0839_")).resolve()
DATA_DIR = BASE_DIR / "data"
ROOT_DIR = DATA_DIR / "client_keys"
BACKUP_DIR = DATA_DIR / "client_keys_original"
OUTSIDE_DIR = BASE_DIR / "outside"

failures = 0
inconclusive = 0
active_case = None


def report(message):
    print(message, flush=True)


def restore_root():
    # Remove only the test-created link, never its target.
    try:
        if ROOT_DIR.is_symlink():
            ROOT_DIR.unlink()

        if BACKUP_DIR.exists() and not ROOT_DIR.exists():
            BACKUP_DIR.rename(ROOT_DIR)

    except OSError as exc:
        report(
            f"[CLEANUP WARNING] Root restoration failed: "
            f"{type(exc).__name__}: {exc}"
        )
        raise


def get_client_root_with_race():
    global active_case

    # This performs the real validation first.
    trusted_root = original_get_client_root()

    if active_case is None:
        return trusted_root

    active_case["calls"] += 1

    # First call is made by _get_private_key_path().
    # On the second call the operation has resolved its file path;
    # the root is validated here and then substituted before os.open().
    if active_case["calls"] == 2 and not active_case["injected"]:
        try:
            ROOT_DIR.rename(BACKUP_DIR)

            try:
                ROOT_DIR.symlink_to(
                    OUTSIDE_DIR,
                    target_is_directory=True
                )
            except Exception:
                if BACKUP_DIR.exists() and not ROOT_DIR.exists():
                    BACKUP_DIR.rename(ROOT_DIR)
                raise

            active_case["injected"] = True

            report(
                "[ATTACK INJECTED] Root directory replaced "
                "after validation, before file open."
            )

        except Exception as exc:
            active_case["injection_error"] = (
                f"{type(exc).__name__}: {exc}"
            )
            report(
                f"[INJECTION FAILED] "
                f"{active_case['injection_error']}"
            )

    return trusted_root


def run_case(username, operation, outside_path, expected_safe_data):
    global failures, inconclusive, active_case

    internal_path = ROOT_DIR / f"{username}.key"
    before = outside_path.read_bytes()

    active_case = {
        "username": username,
        "calls": 0,
        "injected": False,
        "injection_error": None,
    }

    report(f"\n--- {operation.upper()} ---")

    blocked = False
    returned_data = None

    try:
        if operation == "read":
            returned_data = client_storage.load_private_key(username)
            report(f"[RETURNED] {returned_data!r}")
        else:
            client_storage.save_private_key(username, ATTACK_WRITE)
            report("[RETURNED] save_private_key completed")

    except (ValueError, OSError) as exc:
        blocked = True
        report(f"[OPERATION REJECTED] {type(exc).__name__}: {exc}")

    except Exception as exc:
        failures += 1
        report(f"[FAIL] Unexpected exception: {type(exc).__name__}: {exc}")

    finally:
        active_case = None

    # Restore the legitimate directory before examining either target.
    try:
        restore_root()
    except OSError:
        failures += 1
        inconclusive += 1
        return

    if active_case is not None:
        active_case = None

    # The attack must actually have occurred to count as a security test.
    # Preserve the case state locally because active_case has been cleared.
    # The state is retained in the per-case variable below in main.

    after = outside_path.read_bytes()

    if after != before:
        failures += 1
        report(f"[FAIL] External file changed: {after!r}")
        outside_path.write_bytes(before)
    else:
        report("[PASS] External file remains unchanged.")

    if blocked:
        report("[PASS] Operation rejected the substituted root.")
    else:
        if operation == "read" and returned_data == before:
            failures += 1
            report("[FAIL] External file contents were returned.")
        elif operation == "write" and after != before:
            failures += 1
            report("[FAIL] External file was overwritten.")
        else:
            failures += 1
            report("[FAIL] Operation did not reject the substitution.")

    if not internal_path.exists():
        failures += 1
        report("[FAIL] Original internal file is missing.")
    elif internal_path.read_bytes() != expected_safe_data:
        failures += 1
        report("[FAIL] Original internal file changed.")
    else:
        report("[PASS] Original internal file remains unchanged.")


def main():
    global failures, inconclusive, active_case

    try:
        ROOT_DIR.mkdir(parents=True)
        OUTSIDE_DIR.mkdir(parents=True)

        (ROOT_DIR / f"{READ_USERNAME}.key").write_bytes(SAFE_READ)
        (ROOT_DIR / f"{WRITE_USERNAME}.key").write_bytes(SAFE_WRITE)
        (ROOT_DIR / f"{NORMAL_USERNAME}.key").write_bytes(NORMAL_MARKER)

        outside_read_path = OUTSIDE_DIR / f"{READ_USERNAME}.key"
        outside_write_path = OUTSIDE_DIR / f"{WRITE_USERNAME}.key"

        outside_read_path.write_bytes(OUTSIDE_READ)
        outside_write_path.write_bytes(OUTSIDE_WRITE)

        client_storage.CLIENT_DATA_PATH = ROOT_DIR

        report("========== V0.8.39 ROOT TOCTOU TEST ==========")
        report(f"Isolated root: {ROOT_DIR}")
        report(f"External directory: {OUTSIDE_DIR}")

        report("\n[1] NORMAL STORAGE BASELINE")
        client_storage.save_private_key(NORMAL_USERNAME, NORMAL_MARKER)

        if client_storage.load_private_key(NORMAL_USERNAME) == NORMAL_MARKER:
            report("[PASS] Normal storage baseline works.")
        else:
            failures += 1
            report("[FAIL] Normal storage baseline failed.")

        client_storage._get_client_root = get_client_root_with_race

        report("\n[2] READ RACE")
        run_case(
            READ_USERNAME,
            "read",
            outside_read_path,
            SAFE_READ
        )

        report("\n[3] WRITE RACE")
        run_case(
            WRITE_USERNAME,
            "write",
            outside_write_path,
            SAFE_WRITE
        )

        report("\n[4] NORMAL STORAGE AFTER ATTACK")
        if (
            client_storage.load_private_key(NORMAL_USERNAME)
            == NORMAL_MARKER
        ):
            report("[PASS] Normal storage still works.")
        else:
            failures += 1
            report("[FAIL] Normal storage regression detected.")

    except Exception as exc:
        failures += 1
        report(
            f"[FAIL] Test setup/execution error: "
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        active_case = None
        client_storage._get_client_root = original_get_client_root
        client_storage.CLIENT_DATA_PATH = original_client_data_path

        try:
            restore_root()
        except OSError:
            pass

        shutil.rmtree(BASE_DIR, ignore_errors=True)

    report("\n========== V0.8.39 SUMMARY ==========")
    report(f"Failures: {failures}")
    report(f"Inconclusive: {inconclusive}")

    if failures:
        report("RESULT: FAIL")
        return 1

    if inconclusive:
        report("RESULT: INCONCLUSIVE")
        return 2

    report("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())