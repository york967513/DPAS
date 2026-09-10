import secrets

from app.client_storage import (
    CLIENT_DATA_PATH,
    save_private_key,
    load_private_key,
)


RUN_ID = secrets.token_hex(4)

MARKER = f"V0833_MARKER_{RUN_ID}".encode()

SAFE_USERNAME = f"V0833_SAFE_{RUN_ID}"

ABSOLUTE_USERNAME = (
    f"C:\\Windows\\Temp\\V0833_{RUN_ID}"
)

ADS_USERNAME = (
    f"V0833_ADS_{RUN_ID}:secret"
)

INVALID_USERNAME = (
    f"V0833_INVALID_{RUN_ID}<"
)

CONTROL_USERNAME = (
    f"V0833_CONTROL_{RUN_ID}\x01"
)

RESERVED_NAMES = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM9",
    "LPT1",
    "LPT9",
    "CON.txt",
    "NUL.key",
]

TRAILING_NAMES = [
    f"V0833_TRAILING_{RUN_ID}.",
    f"V0833_TRAILING_{RUN_ID} ",
]

failures = 0


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def expect_rejection(
    operation,
    username,
    description
):
    try:

        if operation == "write":
            save_private_key(
                username,
                MARKER
            )
        else:
            load_private_key(
                username
            )

        fail_check(
            description,
            "the storage operation unexpectedly accepted the input"
        )

    except (ValueError, OSError) as exc:
        print(
            f"  Exception: {type(exc).__name__}: {exc}"
        )
        pass_check(
            description
        )


print("=" * 72)
print("DPAS V0.8.33 WINDOWS FILENAME / FILESYSTEM NAMESPACE TEST")
print("=" * 72)

print()
print(f"[SETUP] Test namespace: {RUN_ID}")
print(f"[SETUP] Client key directory: {CLIENT_DATA_PATH.resolve()}")

try:

    # ============================================================
    # 1. STORAGE BOUNDARY
    # ============================================================

    print()
    print("[1] STORAGE BOUNDARY")
    print()
    print("WHAT WE CHECK:")
    print("Verifies the directory used for client private-key files.")
    print()
    print("VULNERABILITY TYPE:")
    print("Filesystem namespace abuse / filename validation.")
    print()
    print("SAFE RESULT:")
    print("All accepted username-derived files remain inside client_keys.")

    if CLIENT_DATA_PATH.exists():
        pass_check(
            "Client key directory exists"
        )
    else:
        fail_check(
            "Client key directory",
            "directory does not exist"
        )

    # ============================================================
    # 2. NORMAL FILE
    # ============================================================

    print()
    print("[2] NORMAL FILE STORAGE")
    print()
    print("WHAT WE CHECK:")
    print("Confirms that legitimate filenames still work.")
    print()
    print("VULNERABILITY TYPE:")
    print("Functional regression control.")
    print()
    print("SAFE RESULT:")
    print("Normal username creates and reads a regular file.")

    save_private_key(
        SAFE_USERNAME,
        MARKER
    )

    safe_file = (
        CLIENT_DATA_PATH
        / f"{SAFE_USERNAME}.key"
    )

    if (
        safe_file.exists()
        and safe_file.is_file()
        and safe_file.read_bytes() == MARKER
    ):
        pass_check(
            "Normal filename storage works correctly"
        )
    else:
        fail_check(
            "Normal filename storage",
            f"unexpected result at {safe_file}"
        )

    if load_private_key(SAFE_USERNAME) == MARKER:
        pass_check(
            "Normal filename read works correctly"
        )
    else:
        fail_check(
            "Normal filename read",
            "stored marker was not returned"
        )

    # ============================================================
    # 3. ABSOLUTE PATH
    # ============================================================

    print()
    print("[3] ABSOLUTE PATH INJECTION")
    print()
    print("WHAT WE CHECK:")
    print("Tests whether username can supply an absolute Windows path.")
    print()
    print("VULNERABILITY TYPE:")
    print("Path Injection / Absolute Path Escape.")
    print()
    print("SAFE RESULT:")
    print("Both write and read operations reject the input.")

    expect_rejection(
        "write",
        ABSOLUTE_USERNAME,
        "Absolute-path write input was rejected"
    )

    expect_rejection(
        "read",
        ABSOLUTE_USERNAME,
        "Absolute-path read input was rejected"
    )

    # ============================================================
    # 4. WINDOWS RESERVED DEVICE NAMES
    # ============================================================

    print()
    print("[4] WINDOWS RESERVED DEVICE NAMES")
    print()
    print("WHAT WE CHECK:")
    print("Tests Windows device namespace names that are not normal files.")
    print()
    print("VULNERABILITY TYPE:")
    print("Special filename / device namespace abuse.")
    print()
    print("EXAMPLES:")
    print("CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9")
    print()
    print("WHY IT MATTERS:")
    print("A private-key storage function must never map a username")
    print("to a special Windows device.")
    print()
    print("SAFE RESULT:")
    print("Every reserved device name is rejected on write and read.")

    for name in RESERVED_NAMES:

        print()
        print(f"  TEST NAME: {name}")

        expect_rejection(
            "write",
            name,
            f"Reserved device write rejected: {name}"
        )

        expect_rejection(
            "read",
            name,
            f"Reserved device read rejected: {name}"
        )

    # ============================================================
    # 5. ALTERNATE DATA STREAM
    # ============================================================

    print()
    print("[5] WINDOWS ALTERNATE DATA STREAM (ADS)")
    print()
    print("WHAT WE CHECK:")
    print("Tests whether colon syntax can address an NTFS alternate stream.")
    print()
    print("VULNERABILITY TYPE:")
    print("Windows ADS / filename namespace abuse.")
    print()
    print("WHY IT MATTERS:")
    print("A path can remain physically inside client_keys while the")
    print("colon changes what Windows considers the file target.")
    print()
    print("SAFE RESULT:")
    print("Colon-based username input is rejected before filesystem access.")

    expect_rejection(
        "write",
        ADS_USERNAME,
        "ADS-style write input was rejected"
    )

    expect_rejection(
        "read",
        ADS_USERNAME,
        "ADS-style read input was rejected"
    )

    # ============================================================
    # 6. INVALID WINDOWS CHARACTER
    # ============================================================

    print()
    print("[6] INVALID WINDOWS FILENAME CHARACTER")
    print()
    print("WHAT WE CHECK:")
    print("Tests characters that Windows does not allow in ordinary filenames.")
    print()
    print("VULNERABILITY TYPE:")
    print("Filename validation.")
    print()
    print("SAFE RESULT:")
    print("The invalid filename is rejected before normal file access.")

    expect_rejection(
        "write",
        INVALID_USERNAME,
        "Invalid-character write input was rejected"
    )

    expect_rejection(
        "read",
        INVALID_USERNAME,
        "Invalid-character read input was rejected"
    )

    # ============================================================
    # 7. CONTROL CHARACTER
    # ============================================================

    print()
    print("[7] CONTROL CHARACTER")
    print()
    print("WHAT WE CHECK:")
    print("Tests a username containing a control character.")
    print()
    print("VULNERABILITY TYPE:")
    print("Control-character / filename input validation.")
    print()
    print("SAFE RESULT:")
    print("Control-character input is rejected on both read and write.")

    expect_rejection(
        "write",
        CONTROL_USERNAME,
        "Control-character write input was rejected"
    )

    expect_rejection(
        "read",
        CONTROL_USERNAME,
        "Control-character read input was rejected"
    )

    # ============================================================
    # 8. TRAILING DOT / SPACE
    # ============================================================

    print()
    print("[8] TRAILING DOT / SPACE")
    print()
    print("WHAT WE CHECK:")
    print("Tests names that Windows may normalize because of trailing")
    print("periods or spaces.")
    print()
    print("VULNERABILITY TYPE:")
    print("Filename canonicalization / namespace confusion.")
    print()
    print("SAFE RESULT:")
    print("Ambiguous trailing-dot and trailing-space names are rejected.")

    for name in TRAILING_NAMES:

        print()
        print(f"  TEST NAME: {repr(name)}")

        expect_rejection(
            "write",
            name,
            "Trailing-character write input was rejected"
        )

        expect_rejection(
            "read",
            name,
            "Trailing-character read input was rejected"
        )

    # ============================================================
    # 9. FINAL SAFETY CHECK
    # ============================================================

    print()
    print("[9] FINAL SAFETY CHECK")
    print()
    print("WHAT WE CHECK:")
    print("Confirms that malicious inputs did not leave marker files.")
    print()
    print("VULNERABILITY TYPE:")
    print("Post-test filesystem integrity.")
    print()
    print("SAFE RESULT:")
    print("Only the legitimate temporary file exists before cleanup.")

    unexpected = []

    for path in CLIENT_DATA_PATH.glob(
        f"V0833_*_{RUN_ID}*"
    ):
        unexpected.append(path)

    outside_files = [
        CLIENT_DATA_PATH.parent
        / f"V0833_{RUN_ID}.key"
    ]

    for path in outside_files:
        if path.exists():
            unexpected.append(path)

    # The safe file is expected.
    unexpected = [
        path
        for path in unexpected
        if path.resolve() != safe_file.resolve()
    ]

    if not unexpected:
        pass_check(
            "No unexpected V0.8.33 marker files were created"
        )
    else:
        fail_check(
            "Unexpected marker files",
            ", ".join(str(path) for path in unexpected)
        )

    # ============================================================
    # 10. CLEANUP
    # ============================================================

    print()
    print("[10] CLEANUP")
    print()
    print("WHAT WE CHECK:")
    print("Removes the legitimate temporary file created by this test.")
    print()
    print("VULNERABILITY TYPE:")
    print("Test isolation / filesystem hygiene.")
    print()
    print("SAFE RESULT:")
    print("No V0.8.33 temporary file remains.")

    if safe_file.exists():
        safe_file.unlink()
        print(
            f"  Removed: {safe_file}"
        )

    if not safe_file.exists():
        pass_check(
            "Temporary test file removed"
        )
    else:
        fail_check(
            "Cleanup verification",
            f"file still exists: {safe_file}"
        )

finally:

    print()
    print("=" * 72)

    if failures == 0:
        print("V0.8.33 RESULT: PASS")
        print("Windows filename namespace protection is working.")
        print("Client key filesystem access remains safely constrained.")
    else:
        print(f"V0.8.33 RESULT: FAIL ({failures} failure(s))")
        print("At least one Windows filesystem namespace issue remains.")

    print("=" * 72)
