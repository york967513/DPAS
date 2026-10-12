import os
import secrets
import shutil
import sys
from pathlib import Path

import app.client_storage as client_storage


CLIENT_DATA_PATH = Path(client_storage.CLIENT_DATA_PATH)
CLIENT_DATA_PATH.mkdir(parents=True, exist_ok=True)

RUN_ID = secrets.token_hex(5)
OUTSIDE_DIR = (CLIENT_DATA_PATH.parent / f"v0837_outside_{RUN_ID}").resolve()

cases = [
    {
        "name": "READ_SYMLINK",
        "username": f"V0837ReadSym{RUN_ID}",
        "kind": "symlink",
        "operation": "read",
        "target_name": "read_symlink_target.key",
        "marker": b"OUTSIDE_READ_SYMLINK_MARKER",
    },
    {
        "name": "READ_HARDLINK",
        "username": f"V0837ReadHard{RUN_ID}",
        "kind": "hardlink",
        "operation": "read",
        "target_name": "read_hardlink_target.key",
        "marker": b"OUTSIDE_READ_HARDLINK_MARKER",
    },
    {
        "name": "WRITE_SYMLINK",
        "username": f"V0837WriteSym{RUN_ID}",
        "kind": "symlink",
        "operation": "write",
        "target_name": "write_symlink_target.key",
        "marker": b"OUTSIDE_WRITE_SYMLINK_MARKER",
    },
    {
        "name": "WRITE_HARDLINK",
        "username": f"V0837WriteHard{RUN_ID}",
        "kind": "hardlink",
        "operation": "write",
        "target_name": "write_hardlink_target.key",
        "marker": b"OUTSIDE_WRITE_HARDLINK_MARKER",
    },
]

normal_username = f"V0837Normal{RUN_ID}"
normal_marker = b"V0837_NORMAL_STORAGE_OK"

triggered = set()
injection_errors = {}
specs = {}
internal_paths = []

def report(message):
    print(message, flush=True)

def main():
    failures = 0
    inconclusive = 0
    original_get_path = client_storage._get_private_key_path

    try:
        OUTSIDE_DIR.mkdir(parents=True, exist_ok=True)

        # Prepare normal in-root files and external marker files.
        for case in cases:
            internal_path = CLIENT_DATA_PATH / f"{case['username']}.key"
            internal_path.write_bytes(b"SAFE_INTERNAL_KEY")
            internal_paths.append(internal_path)

            target = OUTSIDE_DIR / case["target_name"]
            target.write_bytes(case["marker"])
            case["target"] = target
            case["original_marker"] = target.read_bytes()

            specs[case["username"]] = case

        normal_path = CLIENT_DATA_PATH / f"{normal_username}.key"
        normal_path.write_bytes(normal_marker)
        internal_paths.append(normal_path)

        def get_path_with_preopen_attack(username):
            # The original function validates and resolves the path first.
            resolved_path = original_get_path(username)

            case = specs.get(username)
            if case is None or username in triggered:
                return resolved_path

            # Simulate an attacker replacing the pathname after resolution,
            # but before the production code calls os.open().
            triggered.add(username)

            try:
                resolved_path.unlink(missing_ok=True)

                if case["kind"] == "symlink":
                    resolved_path.symlink_to(case["target"])
                else:
                    os.link(case["target"], resolved_path)

                report(
                    f"[ATTACK INJECTED] {case['name']}: "
                    "pathname replaced after resolution, before open"
                )

            except Exception as exc:
                injection_errors[username] = (
                    f"{type(exc).__name__}: {exc}"
                )
                report(
                    f"[INJECTION FAILED] {case['name']}: "
                    f"{injection_errors[username]}"
                )

                # Attempt to restore a regular in-root file if setup failed.
                try:
                    resolved_path.unlink(missing_ok=True)
                    resolved_path.write_bytes(b"SAFE_RESTORED")
                except Exception as restore_exc:
                    report(
                        f"[RESTORE WARNING] {case['name']}: "
                        f"{type(restore_exc).__name__}: {restore_exc}"
                    )

            return resolved_path

        client_storage._get_private_key_path = get_path_with_preopen_attack

        for case in cases:
            name = case["name"]
            username = case["username"]
            target = case["target"]
            before = target.read_bytes()

            report(f"\n--- {name} ---")

            if case["operation"] == "read":
                try:
                    result = client_storage.load_private_key(username)
                    blocked = False
                    report(
                        "[NOT BLOCKED] load_private_key returned "
                        f"{result!r}"
                    )
                except (ValueError, OSError) as exc:
                    blocked = True
                    report(
                        f"[ATTACK BLOCKED] {type(exc).__name__}: {exc}"
                    )
            else:
                try:
                    client_storage.save_private_key(
                        username,
                        b"ATTACKER_CONTROLLED_PRIVATE_KEY"
                    )
                    blocked = False
                    report(
                        "[NOT BLOCKED] save_private_key completed"
                    )
                except (ValueError, OSError) as exc:
                    blocked = True
                    report(
                        f"[ATTACK BLOCKED] {type(exc).__name__}: {exc}"
                    )

            if username in injection_errors:
                inconclusive += 1
                report(
                    f"[INCONCLUSIVE] {name}: substitution was not "
                    "successfully injected."
                )
                continue

            if username not in triggered:
                failures += 1
                report(
                    f"[FAIL] {name}: the pre-open attack hook did not run."
                )
                continue

            if not blocked:
                failures += 1
                report(f"[FAIL] {name}: the attack was not rejected.")
            else:
                report(f"[PASS] {name}: the operation was rejected.")

            after = target.read_bytes()
            if after != before:
                failures += 1
                report(
                    f"[FAIL] {name}: external target contents changed."
                )
            else:
                report(
                    f"[PASS] {name}: external target remains unchanged."
                )

        # Verify normal storage behavior still works.
        report("\n--- NORMAL STORAGE REGRESSION ---")
        try:
            loaded = client_storage.load_private_key(normal_username)
            if loaded != normal_marker:
                failures += 1
                report(
                    f"[FAIL] normal read returned unexpected data: {loaded!r}"
                )
            else:
                client_storage.save_private_key(
                    normal_username,
                    b"V0837_NORMAL_WRITE_OK"
                )
                verified = client_storage.load_private_key(normal_username)

                if verified == b"V0837_NORMAL_WRITE_OK":
                    report("[PASS] normal read/write works.")
                else:
                    failures += 1
                    report("[FAIL] normal write verification failed.")

        except Exception as exc:
            failures += 1
            report(
                f"[FAIL] normal storage raised "
                f"{type(exc).__name__}: {exc}"
            )

    finally:
        client_storage._get_private_key_path = original_get_path

        for path in internal_paths:
            try:
                path.unlink(missing_ok=True)
            except Exception as exc:
                report(
                    f"[CLEANUP WARNING] {path}: "
                    f"{type(exc).__name__}: {exc}"
                )

        try:
            shutil.rmtree(OUTSIDE_DIR, ignore_errors=True)
        except Exception:
            pass

    report("\n========== V0.8.37 SUMMARY ==========")
    report(f"Failures: {failures}")
    report(f"Inconclusive: {inconclusive}")

    if failures:
        report("RESULT: FAIL")
        return 1

    if inconclusive:
        report("RESULT: INCONCLUSIVE — some attacks could not be injected.")
        return 2

    report("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())