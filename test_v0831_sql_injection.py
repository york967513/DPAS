import hashlib
import secrets

from app.database import (
    get_connection,
    get_user,
    create_user,
    get_challenge,
    save_challenge,
    mark_challenge_used,
    get_session,
    create_session,
    create_role,
    create_permission,
    assign_role_to_user,
    assign_permission_to_role,
    user_has_permission,
    delete_user,
)
from app.auth import register_user


RUN_ID = secrets.token_hex(4)

TEST_USER = f"V0831_SQL_{RUN_ID}"
TEST_PASSWORD = "DPAS_SQL_Test_Password_2026!"
TEST_ROLE = f"V0831_ROLE_{RUN_ID}"
TEST_PERMISSION = f"V0831_PERMISSION_{RUN_ID}"

SQL_USERNAME = f"admin' OR '1'='1"
SQL_ROLE = f"role'; DROP TABLE users; --"
SQL_PERMISSION = f"permission' OR '1'='1"
SQL_CHALLENGE = f"challenge'; DROP TABLE challenges; --"
SQL_TOKEN_TEXT = "token' OR '1'='1"

failures = 0


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def table_exists(table_name):
    connection = get_connection()

    row = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table_name,)
    ).fetchone()

    connection.close()

    return row is not None


def count_rows(table_name):
    connection = get_connection()

    count = connection.execute(
        f"SELECT COUNT(*) FROM {table_name}"
    ).fetchone()[0]

    connection.close()

    return count


print("=" * 72)
print("DPAS V0.8.31 SQL INJECTION / DATABASE QUERY BOUNDARY TEST")
print("=" * 72)

try:

    print()
    print(f"[SETUP] Test namespace: {RUN_ID}")
    print(f"[SETUP] Test user: {TEST_USER}")
    print(f"[SETUP] Test role: {TEST_ROLE}")
    print(f"[SETUP] Test permission: {TEST_PERMISSION}")

    # ============================================================
    # 1. DATABASE STRUCTURE BASELINE
    # ============================================================

    print()
    print()
    print("[1] DATABASE STRUCTURE BASELINE")
    print()
    print("  WHAT WE CHECK:")
    print("  Verifies that all security-critical database tables exist before testing.")
    print("  VULNERABILITY TYPE:")
    print("  Database integrity / destructive SQL injection baseline.")
    print("  PURPOSE:")
    print("  Establishes a known-good database state before attack inputs are tested.")
    print("  SAFE RESULT:")
    print("  All required tables must exist before the injection tests begin.")

    required_tables = [
        "users",
        "challenges",
        "sessions",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "audit_log",
    ]

    structure_ok = True

    for table in required_tables:
        exists = table_exists(table)

        if exists:
            pass_check(f"Table exists: {table}")
        else:
            fail_check(
                f"Required table missing: {table}",
                "table was not found before the injection tests"
            )
            structure_ok = False

    if not structure_ok:
        raise RuntimeError("Database baseline is incomplete")

    baseline_users = count_rows("users")
    baseline_challenges = count_rows("challenges")
    baseline_sessions = count_rows("sessions")
    baseline_roles = count_rows("roles")
    baseline_permissions = count_rows("permissions")

    print()
    print("[INFO] Baseline row counts:")
    print(f"        users       = {baseline_users}")
    print(f"        challenges  = {baseline_challenges}")
    print(f"        sessions    = {baseline_sessions}")
    print(f"        roles       = {baseline_roles}")
    print(f"        permissions = {baseline_permissions}")

    # ============================================================
    # 2. USERNAME SQL INJECTION
    # ============================================================

    print()
    print()
    print("[2] USERNAME SQL INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests whether attacker-controlled username input can change SQL query logic.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection (SQLi).")
    print("  ATTACK IDEA:")
    print("  Input such as admin' OR '1'='1 can alter a vulnerable WHERE clause.")
    print("  With parameterized SQL, the entire input remains ordinary string data.")
    print("  SAFE RESULT:")
    print("  The injected username must not match an unrelated account.")

    result = get_user(SQL_USERNAME)

    if result is None:
        pass_check(
            "SQL-like username is treated as data and matches no account"
        )
    else:
        fail_check(
            "Username SQL injection boundary",
            f"unexpected user returned: {result}"
        )

    # ============================================================
    # 3. REAL TEST USER CREATION
    # ============================================================

    print()
    print()
    print("[3] TEST USER CREATION")
    print()
    print("  WHAT WE CHECK:")
    print("  Confirms that normal user creation still works after the previous attack input.")
    print("  VULNERABILITY TYPE:")
    print("  Functional integrity / security regression control.")
    print("  PURPOSE:")
    print("  Security controls must not break legitimate database operations.")
    print("  SAFE RESULT:")
    print("  The normal test user is created and retrieved correctly.")

    registered = register_user(
        TEST_USER,
        TEST_PASSWORD
    )

    if registered is not None:
        pass_check("Dedicated SQL injection test user created")
    else:
        fail_check(
            "Test user creation",
            "register_user returned None"
        )

    stored_user = get_user(TEST_USER)

    if stored_user is not None and stored_user[1] == TEST_USER:
        pass_check("Normal username stored correctly")
    else:
        fail_check(
            "Normal username retrieval",
            f"unexpected stored record: {stored_user}"
        )

    # ============================================================
    # 4. CHALLENGE INJECTION
    # ============================================================

    print()
    print()
    print("[4] CHALLENGE INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests whether attacker-controlled challenge text can become executable SQL.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection / destructive SQL injection attempt.")
    print("  ATTACK IDEA:")
    print("  The payload contains SQL-looking syntax including DROP TABLE and comments.")
    print("  The database must treat the complete value as plain challenge data.")
    print("  SAFE RESULT:")
    print("  The exact challenge string is stored and retrieved unchanged.")

    save_challenge(
        TEST_USER,
        SQL_CHALLENGE
    )

    stored_challenge = get_challenge(
        TEST_USER,
        SQL_CHALLENGE
    )

    if (
        stored_challenge is not None
        and stored_challenge[1] == TEST_USER
        and stored_challenge[2] == SQL_CHALLENGE
        and stored_challenge[4] == 0
    ):
        pass_check(
            "SQL-like challenge is stored as literal data"
        )
    else:
        fail_check(
            "Challenge SQL injection boundary",
            f"unexpected stored challenge: {stored_challenge}"
        )

    # ============================================================
    # 5. CHALLENGE UPDATE INJECTION
    # ============================================================

    print()
    print()
    print("[5] CHALLENGE UPDATE INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests whether challenge input can modify unintended database rows.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection against UPDATE operations / data integrity attack.")
    print("  PURPOSE:")
    print("  A vulnerable UPDATE could modify many records instead of one exact record.")
    print("  SAFE RESULT:")
    print("  Only the exact matching challenge record is changed.")

    updated = mark_challenge_used(
        TEST_USER,
        SQL_CHALLENGE
    )

    after_update = get_challenge(
        TEST_USER,
        SQL_CHALLENGE
    )

    if updated is True and after_update is not None and after_update[4] == 1:
        pass_check(
            "SQL-like challenge updates only its exact record"
        )
    else:
        fail_check(
            "Challenge update boundary",
            f"updated={updated}, stored={after_update}"
        )

    # ============================================================
    # 6. SESSION TOKEN INJECTION
    # ============================================================

    print()
    print()
    print("[6] SESSION TOKEN INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests whether SQL-like token input can manipulate session lookup.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection against authentication/session data.")
    print("  SECURITY IMPACT:")
    print("  Successful manipulation could expose or confuse session identity.")
    print("  SAFE RESULT:")
    print("  An SQL-like token must not resolve to a real session.")

    sql_token_hash = hashlib.sha256(
        SQL_TOKEN_TEXT.encode()
    ).digest()

    session = get_session(sql_token_hash)

    if session is None:
        pass_check(
            "SQL-like token value does not match a real session"
        )
    else:
        fail_check(
            "Session token SQL injection boundary",
            f"unexpected session returned: {session}"
        )

    # ============================================================
    # 7. ROLE NAME INJECTION
    # ============================================================

    print()
    print()
    print("[7] ROLE NAME INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests SQL injection resistance in RBAC role management.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection affecting authorization data.")
    print("  SECURITY IMPACT:")
    print("  Role data influences which permissions a user can receive.")
    print("  SAFE RESULT:")
    print("  SQL-looking role input is stored only as literal role data.")

    injected_role_id = create_role(SQL_ROLE)

    connection = get_connection()

    role_row = connection.execute(
        """
        SELECT id, name
        FROM roles
        WHERE name = ?
        """,
        (SQL_ROLE,)
    ).fetchone()

    connection.close()

    if role_row is not None and role_row[0] == injected_role_id and role_row[1] == SQL_ROLE:
        pass_check(
            "SQL-like role name is stored as literal data"
        )
    else:
        fail_check(
            "Role SQL injection boundary",
            f"unexpected role row: {role_row}"
        )

    # ============================================================
    # 8. PERMISSION NAME INJECTION
    # ============================================================

    print()
    print()
    print("[8] PERMISSION NAME INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests SQL injection resistance in permission management.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection affecting authorization policy data.")
    print("  SECURITY IMPACT:")
    print("  Manipulated permission data or lookups could contribute to authorization bypass.")
    print("  SAFE RESULT:")
    print("  SQL-looking permission input is treated only as data.")

    injected_permission_id = create_permission(SQL_PERMISSION)

    connection = get_connection()

    permission_row = connection.execute(
        """
        SELECT id, name
        FROM permissions
        WHERE name = ?
        """,
        (SQL_PERMISSION,)
    ).fetchone()

    connection.close()

    if (
        permission_row is not None
        and permission_row[0] == injected_permission_id
        and permission_row[1] == SQL_PERMISSION
    ):
        pass_check(
            "SQL-like permission name is stored as literal data"
        )
    else:
        fail_check(
            "Permission SQL injection boundary",
            f"unexpected permission row: {permission_row}"
        )

    # ============================================================
    # 9. NORMAL ROLE/PERMISSION ASSOCIATION
    # ============================================================

    print()
    print()
    print("[9] NORMAL ROLE / PERMISSION ASSOCIATION")
    print()
    print("  WHAT WE CHECK:")
    print("  Confirms that legitimate RBAC relationships still work.")
    print("  VULNERABILITY TYPE:")
    print("  Authorization integrity / regression control.")
    print("  PURPOSE:")
    print("  Security testing must not break normal user-role-permission relationships.")
    print("  SAFE RESULT:")
    print("  User -> role -> permission relationships are created and resolved normally.")

    normal_role_id = create_role(TEST_ROLE)
    normal_permission_id = create_permission(TEST_PERMISSION)

    role_assigned = assign_role_to_user(
        TEST_USER,
        TEST_ROLE
    )

    permission_assigned = assign_permission_to_role(
        TEST_ROLE,
        TEST_PERMISSION
    )

    permission_check = user_has_permission(
        TEST_USER,
        TEST_PERMISSION
    )

    if role_assigned:
        pass_check("Normal test role assigned to test user")
    else:
        fail_check(
            "Role assignment",
            "assign_role_to_user returned False"
        )

    if permission_assigned:
        pass_check("Normal test permission assigned to test role")
    else:
        fail_check(
            "Permission assignment",
            "assign_permission_to_role returned False"
        )

    if permission_check:
        pass_check("Normal permission relationship works")
    else:
        fail_check(
            "Permission relationship",
            "user_has_permission returned False"
        )

    # ============================================================
    # 10. INJECTION INTO AUTHORIZATION LOOKUP
    # ============================================================

    print()
    print()
    print("[10] AUTHORIZATION LOOKUP INJECTION")
    print()
    print("  WHAT WE CHECK:")
    print("  Tests whether SQL-like permission input can change an authorization decision.")
    print("  VULNERABILITY TYPE:")
    print("  SQL Injection with potential Authorization Bypass.")
    print("  SECURITY IMPACT:")
    print("  A manipulated permission lookup could grant access that should be denied.")
    print("  SAFE RESULT:")
    print("  The injected permission string must not grant a real permission.")

    injected_permission_check = user_has_permission(
        TEST_USER,
        SQL_PERMISSION
    )

    if not injected_permission_check:
        pass_check(
            "SQL-like permission name cannot alter authorization lookup"
        )
    else:
        fail_check(
            "Authorization SQL injection boundary",
            "SQL-like permission unexpectedly produced a permission match"
        )

    # ============================================================
    # 11. DATABASE STRUCTURE AFTER INJECTION ATTEMPTS
    # ============================================================

    print()
    print()
    print("[11] DATABASE STRUCTURE AFTER INJECTION ATTEMPTS")
    print()
    print("  WHAT WE CHECK:")
    print("  Verifies that injection attempts did not destroy security-critical tables.")
    print("  VULNERABILITY TYPE:")
    print("  Destructive SQL Injection / database integrity.")
    print("  PURPOSE:")
    print("  Confirms that attack strings never became executable SQL commands.")
    print("  SAFE RESULT:")
    print("  Every required table still exists after all injection attempts.")

    for table in required_tables:
        if table_exists(table):
            pass_check(
                f"Table still exists after injection tests: {table}"
            )
        else:
            fail_check(
                f"Table disappeared: {table}",
                "database structure changed during the test"
            )

    # ============================================================
    # 12. ROW COUNT SANITY
    # ============================================================

    print()
    print()
    print("[12] ROW COUNT SANITY")
    print()
    print("  WHAT WE CHECK:")
    print("  Performs an additional data-integrity check after injection attempts.")
    print("  VULNERABILITY TYPE:")
    print("  Data tampering / destructive SQL effects.")
    print("  PURPOSE:")
    print("  Table existence alone does not prove that data was not deleted or altered.")
    print("  SAFE RESULT:")
    print("  Critical table populations must not unexpectedly decrease.")

    current_challenges = count_rows("challenges")
    current_sessions = count_rows("sessions")

    if current_challenges >= baseline_challenges:
        pass_check(
            "Challenge table remains intact"
        )
    else:
        fail_check(
            "Challenge row count integrity",
            f"baseline={baseline_challenges}, current={current_challenges}"
        )

    if current_sessions >= baseline_sessions:
        pass_check(
            "Session table remains intact"
        )
    else:
        fail_check(
            "Session row count integrity",
            f"baseline={baseline_sessions}, current={current_sessions}"
        )

    # ============================================================
    # 13. CLEANUP
    # ============================================================

    print()
    print()
    print("[13] CLEANUP")
    print()
    print("  WHAT WE CHECK:")
    print("  Removes only temporary objects created by this security test.")
    print("  VULNERABILITY TYPE:")
    print("  Test isolation / database hygiene.")
    print("  PURPOSE:")
    print("  Keeps later security tests independent and repeatable.")
    print("  SAFE RESULT:")
    print("  Test artifacts are removed without affecting unrelated application data.")

    if delete_user(TEST_USER):
        pass_check("Dedicated test user removed")
    else:
        fail_check(
            "Test user cleanup",
            "delete_user returned False"
        )

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM roles
        WHERE name = ?
        """,
        (SQL_ROLE,)
    )

    connection.execute(
        """
        DELETE FROM roles
        WHERE name = ?
        """,
        (TEST_ROLE,)
    )

    connection.execute(
        """
        DELETE FROM permissions
        WHERE name = ?
        """,
        (SQL_PERMISSION,)
    )

    connection.execute(
        """
        DELETE FROM permissions
        WHERE name = ?
        """,
        (TEST_PERMISSION,)
    )

    connection.execute(
        """
        DELETE FROM challenges
        WHERE username = ?
          AND challenge = ?
        """,
        (TEST_USER, SQL_CHALLENGE)
    )

    connection.commit()
    connection.close()

    pass_check("Injected test artifacts cleaned up using parameterized SQL")

    # ============================================================
    # 14. FINAL DATABASE CHECK
    # ============================================================

    print()
    print()
    print("[14] FINAL DATABASE CHECK")
    print()
    print("  WHAT WE CHECK:")
    print("  Performs a final database integrity verification after cleanup.")
    print("  VULNERABILITY TYPE:")
    print("  Post-test database integrity verification.")
    print("  PURPOSE:")
    print("  Confirms that the database remains usable after the complete test.")
    print("  SAFE RESULT:")
    print("  Core DPAS database tables remain available.")

    if table_exists("users") and table_exists("challenges") and table_exists("sessions"):
        pass_check(
            "Core database tables remain available"
        )
    else:
        fail_check(
            "Final database integrity",
            "one or more core tables are unavailable"
        )

except Exception as exc:
    print()
    print("[EXCEPTION]")
    print(type(exc).__name__)
    print(str(exc))
    failures += 1

finally:
    print()
    print("=" * 72)

    if failures == 0:
        print("V0.8.31 RESULT: PASS")
        print("SQL-like input did not change SQL query semantics.")
        print("Database structure remained intact.")
    else:
        print(f"V0.8.31 RESULT: FAIL ({failures} failure(s))")
        print("Review the failing checks before making any code changes.")

    print("=" * 72)
