import secrets
import sqlite3

from app.database import (
    record_audit_event,
    get_connection,
    delete_user
)
from app.auth import register_user


RUN_ID = secrets.token_hex(4)

TEST_USER = f"V0830Audit_{RUN_ID}"

failures = 0


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def fetch_events_for_user(username):
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            timestamp,
            event_type,
            action,
            result,
            username,
            resource,
            details
        FROM audit_log
        WHERE username = ?
        ORDER BY id
        """,
        (username,)
    ).fetchall()

    connection.close()

    return rows


def fetch_event(event_id):
    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            id,
            timestamp,
            event_type,
            action,
            result,
            username,
            resource,
            details
        FROM audit_log
        WHERE id = ?
        """,
        (event_id,)
    ).fetchone()

    connection.close()

    return row


try:
    print("=" * 70)
    print("DPAS V0.8.30 AUDIT LOG INTEGRITY / LOG INJECTION TEST")
    print("=" * 70)

    print()
    print(f"[SETUP] Unique test namespace: {RUN_ID}")
    print(f"[SETUP] Test user: {TEST_USER}")

    # ============================================================
    # 1. TEST USER
    # ============================================================

    print()
    print("[1] TEST USER")

    result = register_user(
        TEST_USER,
        "DPAS_Test_Password_2026!"
    )

    if result is not None:
        pass_check("Audit test user registered")
    else:
        fail_check(
            "Audit test user registration",
            "registration returned None"
        )

    # ============================================================
    # 2. NORMAL AUDIT EVENT
    # ============================================================

    print()
    print("[2] NORMAL AUDIT EVENT")

    before_events = fetch_events_for_user(
        TEST_USER
    )

    record_audit_event(
        event_type="TEST",
        action="AUDIT_INTEGRITY",
        result="SUCCESS",
        username=TEST_USER,
        resource="v0.8.30",
        details="Normal audit event"
    )

    after_events = fetch_events_for_user(
        TEST_USER
    )

    if len(after_events) == len(before_events) + 1:
        pass_check(
            "Audit event is persisted"
        )
    else:
        fail_check(
            "Audit event persistence",
            "expected exactly one new audit record"
        )

    normal_event = after_events[-1]

    if (
        normal_event[2] == "TEST"
        and normal_event[3] == "AUDIT_INTEGRITY"
        and normal_event[4] == "SUCCESS"
        and normal_event[5] == TEST_USER
        and normal_event[6] == "v0.8.30"
        and normal_event[7] == "Normal audit event"
    ):
        pass_check(
            "Normal audit fields preserved"
        )
    else:
        fail_check(
            "Normal audit fields",
            f"unexpected stored event: {normal_event}"
        )

    # ============================================================
    # 3. CONTROL CHARACTER / NEWLINE INPUT
    # ============================================================

    print()
    print("[3] CONTROL CHARACTER / NEWLINE INPUT")

    injected_details = (
        "line-one\n"
        "line-two\r\n"
        "tab\tvalue\r"
    )

    record_audit_event(
        event_type="TEST",
        action="AUDIT_INJECTION",
        result="FAILURE",
        username=TEST_USER,
        resource="v0.8.30",
        details=injected_details
    )

    events = fetch_events_for_user(
        TEST_USER
    )

    injected_event = events[-1]

    if injected_event[7] == injected_details:
        pass_check(
            "Control characters remain confined to the details field"
        )
    else:
        fail_check(
            "Control character handling",
            "stored audit details differ from supplied data"
        )

    # ============================================================
    # 4. SQL-META CHARACTER INPUT
    #
    # This does not attempt destructive SQL. It checks whether
    # parameterized storage preserves attacker-controlled text.
    # ============================================================

    print()
    print("[4] SQL-META CHARACTER INPUT")

    sql_like_details = (
        "'; DROP TABLE audit_log; -- "
        "/* injected text */"
    )

    record_audit_event(
        event_type="TEST",
        action="SQL_META",
        result="FAILURE",
        username=TEST_USER,
        resource="v0.8.30",
        details=sql_like_details
    )

    sql_event = fetch_events_for_user(
        TEST_USER
    )[-1]

    if sql_event[7] == sql_like_details:
        pass_check(
            "SQL-like audit input stored as data"
        )
    else:
        fail_check(
            "SQL-like audit input",
            "stored value differs from supplied text"
        )

    # ============================================================
    # 5. STRUCTURAL DELIMITER INPUT
    # ============================================================

    print()
    print("[5] STRUCTURAL DELIMITER INPUT")

    delimiter_details = (
        "event_type=AUTHENTICATION;"
        "action=LOGIN;"
        "result=SUCCESS;"
        "username=admin;"
        "resource=/admin"
    )

    record_audit_event(
        event_type="TEST",
        action="DELIMITER",
        result="FAILURE",
        username=TEST_USER,
        resource="v0.8.30",
        details=delimiter_details
    )

    delimiter_event = fetch_events_for_user(
        TEST_USER
    )[-1]

    if (
        delimiter_event[2] == "TEST"
        and delimiter_event[3] == "DELIMITER"
        and delimiter_event[4] == "FAILURE"
        and delimiter_event[5] == TEST_USER
        and delimiter_event[7] == delimiter_details
    ):
        pass_check(
            "Delimiter-like content does not alter audit structure"
        )
    else:
        fail_check(
            "Audit structure integrity",
            f"unexpected stored event: {delimiter_event}"
        )

    # ============================================================
    # 6. NULL-LIKE / EMPTY OPTIONAL VALUES
    # ============================================================

    print()
    print("[6] OPTIONAL FIELD HANDLING")

    record_audit_event(
        event_type="TEST",
        action="OPTIONAL_FIELDS",
        result="SUCCESS",
        username=None,
        resource=None,
        details=None
    )

    connection = get_connection()

    optional_event = connection.execute(
        """
        SELECT
            event_type,
            action,
            result,
            username,
            resource,
            details
        FROM audit_log
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    connection.close()

    if (
        optional_event[0] == "TEST"
        and optional_event[1] == "OPTIONAL_FIELDS"
        and optional_event[2] == "SUCCESS"
        and optional_event[3] is None
        and optional_event[4] is None
        and optional_event[5] is None
    ):
        pass_check(
            "Optional audit fields preserve NULL values"
        )
    else:
        fail_check(
            "Optional audit fields",
            f"unexpected values: {optional_event}"
        )

    # ============================================================
    # 7. RECORD ORDER / ID MONOTONICITY
    # ============================================================

    print()
    print("[7] RECORD ORDER / ID MONOTONICITY")

    events = fetch_events_for_user(
        TEST_USER
    )

    ids = [
        row[0]
        for row in events
    ]

    if len(ids) >= 3 and ids == sorted(ids):
        pass_check(
            "Audit record IDs remain monotonically ordered"
        )
    else:
        fail_check(
            "Audit record ordering",
            f"unexpected IDs: {ids}"
        )

    timestamps_present = all(
        row[1] is not None and row[1] != ""
        for row in events
    )

    if timestamps_present:
        pass_check(
            "Audit records contain timestamps"
        )
    else:
        fail_check(
            "Audit timestamps",
            "one or more records have missing timestamps"
        )

    # ============================================================
    # 8. AUDIT HISTORY SURVIVES USER DELETION
    # ============================================================

    print()
    print("[8] AUDIT HISTORY AFTER USER DELETION")

    pre_delete_events = fetch_events_for_user(
        TEST_USER
    )

    if not delete_user(TEST_USER):
        fail_check(
            "Test user deletion",
            "delete_user returned False"
        )
    else:
        remaining_events = fetch_events_for_user(
            TEST_USER
        )

        if (
            len(remaining_events)
            >= len(pre_delete_events)
        ):
            pass_check(
                "Audit history survives user deletion"
            )
        else:
            fail_check(
                "Audit history retention",
                (
                    f"expected at least {len(pre_delete_events)} "
                    f"events, found {len(remaining_events)}"
                )
            )

    # ============================================================
    # 9. AUDIT TABLE STILL EXISTS
    # ============================================================

    print()
    print("[9] AUDIT TABLE INTEGRITY")

    connection = get_connection()

    table_exists = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'audit_log'
        """
    ).fetchone()

    connection.close()

    if table_exists is not None:
        pass_check(
            "audit_log table remains intact"
        )
    else:
        fail_check(
            "audit_log table integrity",
            "audit_log table is missing"
        )

finally:
    print()
    print("[CLEANUP] Removing remaining test user data")

    try:
        delete_user(TEST_USER)
    except Exception:
        pass

    print()
    print("=" * 70)

    if failures == 0:
        print(
            "V0.8.30 AUDIT LOG INTEGRITY / LOG INJECTION TEST PASSED"
        )
    else:
        print(
            "V0.8.30 AUDIT LOG INTEGRITY / LOG INJECTION TEST FAILED"
        )

    print("=" * 70)

raise SystemExit(1 if failures else 0)
