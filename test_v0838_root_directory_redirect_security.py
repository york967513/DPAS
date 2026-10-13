import secrets
import shutil
import sys
import tempfile
from pathlib import Path

import app.client_storage as client_storage


RUN_ID = secrets.token_hex(5)
READ_USERNAME = f"V0838Read{RUN_ID}"
WRITE_USERNAME = f"V0838Write{RUN_ID}"
NORMAL_USERNAME = f"V0838Normal{RUN_ID}"

OUTSIDE_READ_MARKER = b"V0838_OUTSIDE_READ_SECRET"
OUTSIDE_WRITE_MARKER = b"V0838_OUTSIDE_WRITE_INITIAL"
ATTACK_WRITE_MARKER = b"V0838_ATTACKER_WRITE_PAYLOAD"
NORMAL_MARKER = b"V0838_NORMAL_STORAGE_OK"

failures = 0
inconclusive = 0

original_client_data_path = client_storage.CLIENT_DATA_PATH

BASE_DIR = Path(
    tempfile.mkdtemp(prefix="dpas_v0838_")
).resolve()

DATA_DIR = BASE_DIR / "data"
ROOT_DIR = DATA_DIR / "client_keys"
BACKUP_DIR = DATA_DIR / "client_keys_original"
OUTSIDE_DIR = BASE_DIR / "outside"


def report(message):
    print(message, flush=True)


def main():
    global failures, inconclusive

    link_created = False

    try:
        ROOT_DIR.mkdir(parents=True)
        OUTSIDE_DIR.mkdir(parents=True)

        # Prepare files in the legitimate client-key directory.
        (ROOT_DIR / f"{READ_USERNAME}.key").write_bytes(
            b"SAFE_INTERNAL_READ_KEY"
        )
        (ROOT_DIR / f"{WRITE_USERNAME}.key").write_bytes(
            b"SAFE_INTERNAL_WRITE_KEY"
        )

        # Prepare attacker-controlled files outside client_keys.
        outside_read = OUTSIDE_DIR / f"{READ_USERNAME}.key"
        outside_write = OUTSIDE_DIR / f"{WRITE_USERNAME}.key"

        outside_read.write_bytes(OUTSIDE_READ_MARKER)
        outside_write.write_bytes(OUTSIDE_WRITE_MARKER)

        client_storage.CLIENT_DATA_PATH = ROOT_DIR

        report("========== V0.8.38 ROOT REDIRECTION TEST ==========")
        report(f"Isolated test root: {ROOT_DIR}")
        report(f"External directory: {OUTSIDE_DIR}")

        # Baseline: ordinary file storage must work before the attack.
        report("\n[1] NORMAL STORAGE BASELINE")

        client_storage.save_private_key(
            NORMAL_USERNAME,
            NORMAL_MARKER
        )

        normal_read = client_storage.load_private_key(
            NORMAL_USERNAME
        )

        if normal_read == NORMAL_MARKER:
            report("[PASS] Normal storage works before the attack.")
        else:
            failures += 1
            report("[FAIL] Normal storage baseline failed.")

        # Simulate the client_keys directory being redirected.
        report("\n[2] ROOT DIRECTORY SUBSTITUTION")

        ROOT_DIR.rename(BACKUP_DIR)

        try:
            ROOT_DIR.symlink_to(
                OUTSIDE_DIR,
                target_is_directory=True
            )
            link_created = True
            report(
                "[ATTACK INJECTED] client_keys now points "
                "to the external directory."
            )
        except (OSError, NotImplementedError) as exc:
            inconclusive += 2
            report(
                f"[INCONCLUSIVE] Could not create directory "
                f"symlink: {type(exc).__name__}: {exc}"
            )

        if link_created:
            # Attack 1: try to read the external key through DPAS.
            report("\n[3] EXTERNAL FILE READ")

            try:
                result = client_storage.load_private_key(
                    READ_USERNAME
                )
            except (ValueError, OSError) as exc:
                report(
                    f"[PASS] External read rejected: "
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                if result == OUTSIDE_READ_MARKER:
                    failures += 1
                    report(
                        "[FAIL] VULNERABILITY CONFIRMED: "
                        "DPAS returned the external file contents."
                    )
                elif result is None:
                    inconclusive += 1
                    report(
                        "[INCONCLUSIVE] Read returned None "
                        "instead of explicitly rejecting the redirect."
                    )
                else:
                    inconclusive += 1
                    report(
                        "[INCONCLUSIVE] Read returned unexpected data; "
                        "inspect the result before drawing a conclusion."
                    )

            # Attack 2: try to overwrite an external key.
            report("\n[4] EXTERNAL FILE WRITE")

            before = outside_write.read_bytes()

            try:
                client_storage.save_private_key(
                    WRITE_USERNAME,
                    ATTACK_WRITE_MARKER
                )
            except (ValueError, OSError) as exc:
                report(
                    f"[PASS] External write rejected: "
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                after = outside_write.read_bytes()

                if after != before:
                    failures += 1
                    report(
                        "[FAIL] VULNERABILITY CONFIRMED: "
                        "DPAS modified the external file."
                    )
                    report(f"External file after attack: {after!r}")
                else:
                    inconclusive += 1
                    report(
                        "[INCONCLUSIVE] Write returned successfully, "
                        "but the external file was unchanged."
                    )

            # Ensure the test never leaves its external marker altered.
            outside_write.write_bytes(OUTSIDE_WRITE_MARKER)

    except Exception as exc:
        failures += 1
        report(
            f"\n[FAIL] Test setup or execution raised "
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        client_storage.CLIENT_DATA_PATH = original_client_data_path

        # Remove the directory link itself, not its target.
        try:
            if ROOT_DIR.is_symlink():
                ROOT_DIR.unlink()
        except OSError as exc:
            report(f"[CLEANUP WARNING] Could not remove link: {exc}")

        shutil.rmtree(BASE_DIR, ignore_errors=True)

    report("\n========== V0.8.38 SUMMARY ==========")
    report(f"Failures: {failures}")
    report(f"Inconclusive: {inconclusive}")

    if failures:
        report("RESULT: FAIL — root directory redirection is exploitable.")
        return 1

    if inconclusive:
        report("RESULT: INCONCLUSIVE — more verification is required.")
        return 2

    report("RESULT: PASS — the tested root redirection was rejected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())