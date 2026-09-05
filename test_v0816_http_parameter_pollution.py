from fastapi.testclient import TestClient

from app.api import app
from app.auth import register_user
from app.database import (
    get_connection,
    delete_user,
)
from app.session_manager import (
    create_user_session,
    logout,
)


NORMAL_USER = "V0816Normal"
ADMIN_USER = "V0816Admin"
PASSWORD = "DPAS_Test_Password_2026!"

client = TestClient(app)

failures = 0
normal_token = None
admin_token = None


def cleanup():
    global normal_token
    global admin_token

    for token in (normal_token, admin_token):
        if token:
            try:
                logout(token)
            except Exception:
                pass

    normal_token = None
    admin_token = None

    for username in (
        NORMAL_USER,
        ADMIN_USER,
    ):
        try:
            delete_user(username)
        except Exception:
            pass


def create_user(username):
    register_user(
        username,
        PASSWORD
    )


def add_admin_role(username):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,)
    )
    user_row = cursor.fetchone()

    cursor.execute(
        "SELECT id FROM roles WHERE name = 'admin'"
    )
    role_row = cursor.fetchone()

    if not user_row or not role_row:
        connection.close()
        raise RuntimeError(
            f"Could not configure admin role for {username}"
        )

    cursor.execute(
        """
        INSERT INTO user_roles (user_id, role_id)
        VALUES (?, ?)
        """,
        (user_row[0], role_row[0])
    )

    connection.commit()
    connection.close()


def pass_check(label):
    print(f"[PASS] {label}")


def fail_check(label, details):
    global failures
    print(f"[FAIL] {label}: {details}")
    failures += 1


def expect_status(label, response, expected):
    if response.status_code == expected:
        pass_check(
            f"{label} -> HTTP {response.status_code}"
        )
    else:
        fail_check(
            label,
            f"expected HTTP {expected}, "
            f"got HTTP {response.status_code}"
        )


try:

    # ============================================================
    # SETUP
    # ============================================================

    print("=" * 70)
    print("DPAS V0.8.16 HTTP PARAMETER POLLUTION / REQUEST AMBIGUITY TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated ambiguity test users")

    cleanup()

    create_user(NORMAL_USER)
    create_user(ADMIN_USER)
    add_admin_role(ADMIN_USER)

    normal_token = create_user_session(NORMAL_USER)
    admin_token = create_user_session(ADMIN_USER)

    pass_check("Ambiguity test sessions created")

    normal_headers = {
        "Authorization": f"Bearer {normal_token}"
    }

    admin_headers = {
        "Authorization": f"Bearer {admin_token}"
    }


    # ============================================================
    # 1. DUPLICATE ADMIN QUERY PARAMETERS
    # ============================================================

    print()
    print("[1] DUPLICATE ADMIN QUERY PARAMETERS")

    query_tests = [
        "/admin/users?role=admin&role=user",
        "/admin/users?permission=users.read&permission=users.delete",
        "/admin/users?authorized=true&authorized=false",
        "/admin/users?role=user&role=admin",
        "/admin/users?permission=none&permission=users.read",
    ]

    for path in query_tests:

        response = client.get(
            path,
            headers=normal_headers
        )

        expect_status(
            f"Normal user -> {path}",
            response,
            403
        )


    # ============================================================
    # 2. DUPLICATE QUERY PARAMETERS WITH ADMIN SESSION
    # ============================================================

    print()
    print("[2] DUPLICATE QUERY PARAMETERS WITH ADMIN SESSION")

    response = client.get(
        "/admin/users?role=admin&role=user",
        headers=admin_headers
    )

    expect_status(
        "Admin -> duplicated role parameters",
        response,
        200
    )

    if response.status_code == 200:

        body = response.json()

        if body.get("permission") == "users.read":
            pass_check(
                "Duplicate query parameters did not alter "
                "admin operation"
            )
        else:
            fail_check(
                "Admin duplicated-query response",
                "permission changed unexpectedly"
            )


    # ============================================================
    # 3. DUPLICATE SECURITY-LOOKING PARAMETERS
    # ============================================================

    print()
    print("[3] DUPLICATE SECURITY-LOOKING PARAMETERS")

    attack_paths = [
        "/admin/users?is_admin=false&is_admin=true",
        "/admin/users?authorized=false&authorized=true",
        "/admin/users?permission=none&permission=admin",
        "/admin/users?role=guest&role=admin",
        "/admin/users?access=deny&access=grant",
    ]

    for path in attack_paths:

        response = client.get(
            path,
            headers=normal_headers
        )

        expect_status(
            f"Normal user -> {path}",
            response,
            403
        )


    # ============================================================
    # 4. ARRAY-LIKE QUERY PARAMETERS
    # ============================================================

    print()
    print("[4] ARRAY-LIKE QUERY PARAMETERS")

    array_paths = [
        "/admin/users?role[]=admin",
        "/admin/users?permission[]=users.read",
        "/admin/users?authorized[]=true",
        "/admin/users?is_admin[]=true",
    ]

    for path in array_paths:

        response = client.get(
            path,
            headers=normal_headers
        )

        expect_status(
            f"Normal user -> {path}",
            response,
            403
        )


    # ============================================================
    # 5. QUERY PARAMETER ORDER
    # ============================================================

    print()
    print("[5] QUERY PARAMETER ORDER")

    order_a = client.get(
        "/admin/users?role=admin&permission=users.read",
        headers=normal_headers
    )

    order_b = client.get(
        "/admin/users?permission=users.read&role=admin",
        headers=normal_headers
    )

    if (
        order_a.status_code == 403
        and order_b.status_code == 403
    ):
        pass_check(
            "Reordering security-looking parameters "
            "did not alter authorization"
        )
    else:
        fail_check(
            "Query parameter order",
            f"responses were {order_a.status_code} and "
            f"{order_b.status_code}"
        )


    # ============================================================
    # 6. NORMAL USER STILL CANNOT WRITE PROFILE
    # ============================================================

    print()
    print("[6] NORMAL USER PROFILE-WRITE AUTHORIZATION")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "NormalDenied",
            "role": "admin",
            "permission": "users.delete",
            "is_admin": True,
        },
        headers=normal_headers
    )

    expect_status(
        "Normal user profile.write remains denied",
        response,
        403
    )


    # ============================================================
    # 7. EXTRA JSON FIELDS — ADMIN SESSION
    # ============================================================

    print()
    print("[7] EXTRA JSON FIELDS / PROFILE WRITE")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "V0816AdminName",
            "is_admin": True,
            "role": "admin",
            "permission": "users.delete",
            "authorized": True,
            "username": NORMAL_USER,
        },
        headers=admin_headers
    )

    expect_status(
        "Admin profile write with privilege-looking fields",
        response,
        200
    )

    if response.status_code == 200:

        body = response.json()

        if body.get("username") == ADMIN_USER:
            pass_check(
                "Extra fields did not change session identity"
            )
        else:
            fail_check(
                "Profile write identity",
                "session identity was altered"
            )

        if body.get("permission") == "profile.write":
            pass_check(
                "Extra fields did not change required permission"
            )
        else:
            fail_check(
                "Profile write permission",
                "permission context was altered"
            )

        if body.get("display_name") == "V0816AdminName":
            pass_check(
                "Only declared display_name affected the response"
            )
        else:
            fail_check(
                "Profile write display_name",
                "unexpected value returned"
            )


    # ============================================================
    # 8. PRIVILEGE-LOOKING JSON FIELDS CANNOT ALTER OPERATION
    # ============================================================

    print()
    print("[8] EXTRA JSON FIELDS CANNOT CREATE ADMIN ACCESS")

    response = client.put(
        "/protected/profile/write",
        json={
            "display_name": "AttemptedEscalation",
            "permission": "users.delete",
            "role": "admin",
            "is_admin": True,
        },
        headers=admin_headers
    )

    expect_status(
        "Admin profile write with privilege-looking fields",
        response,
        200
    )

    if response.status_code == 200:

        body = response.json()

        if body.get("permission") == "profile.write":
            pass_check(
                "Privilege-looking JSON fields did not "
                "change endpoint permission"
            )
        else:
            fail_check(
                "Privilege-looking JSON fields",
                "endpoint permission was altered"
            )

        if body.get("username") == ADMIN_USER:
            pass_check(
                "Privilege-looking JSON fields did not "
                "change user identity"
            )
        else:
            fail_check(
                "Privilege-looking identity fields",
                "user identity changed"
            )


    # ============================================================
    # 9. DUPLICATE JSON KEY
    # ============================================================

    print()
    print("[9] DUPLICATE JSON KEY")

    duplicate_json = (
        '{"display_name":"FirstValue",'
        '"display_name":"SecondValue"}'
    )

    response = client.put(
        "/protected/profile/write",
        content=duplicate_json,
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        }
    )

    expect_status(
        "Profile write with duplicate display_name key",
        response,
        200
    )

    if response.status_code == 200:

        body = response.json()
        display_name = body.get("display_name")

        if display_name in (
            "FirstValue",
            "SecondValue",
        ):
            pass_check(
                "Duplicate JSON key produced one "
                "deterministic display_name value"
            )
        else:
            fail_check(
                "Duplicate JSON key",
                f"unexpected display_name: {display_name}"
            )

        if body.get("username") == ADMIN_USER:
            pass_check(
                "Duplicate JSON key did not alter "
                "session identity"
            )
        else:
            fail_check(
                "Duplicate JSON identity",
                "unexpected username"
            )


    # ============================================================
    # 10. DUPLICATE SECURITY FIELDS
    # ============================================================

    print()
    print("[10] DUPLICATE JSON SECURITY FIELDS")

    duplicate_attack_json = (
        '{"display_name":"ControlledName",'
        '"permission":"profile.write",'
        '"permission":"users.delete",'
        '"role":"user",'
        '"role":"admin",'
        '"is_admin":false,'
        '"is_admin":true}'
    )

    response = client.put(
        "/protected/profile/write",
        content=duplicate_attack_json,
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        }
    )

    expect_status(
        "Profile write with duplicate privilege-looking keys",
        response,
        200
    )

    if response.status_code == 200:

        body = response.json()

        if body.get("permission") == "profile.write":
            pass_check(
                "Duplicate privilege-looking fields did not "
                "change endpoint permission"
            )
        else:
            fail_check(
                "Duplicate privilege-looking fields",
                "endpoint permission was altered"
            )

        if body.get("username") == ADMIN_USER:
            pass_check(
                "Duplicate privilege-looking fields did not "
                "change user identity"
            )
        else:
            fail_check(
                "Duplicate privilege-looking identity",
                "user identity changed"
            )


    # ============================================================
    # 11. EXTRA FIELDS ON LOGIN
    # ============================================================

    print()
    print("[11] EXTRA JSON FIELDS ON LOGIN")

    response = client.post(
        "/login",
        json={
            "username": "V0816Unknown",
            "password": PASSWORD,
            "role": "admin",
            "is_admin": True,
            "permission": "users.delete",
        }
    )

    expect_status(
        "Login with privilege-looking extra fields",
        response,
        401
    )


    # ============================================================
    # 12. ARRAY VALUES WHERE SCALAR USERNAME IS EXPECTED
    # ============================================================

    print()
    print("[12] ARRAY VALUES IN SCALAR FIELDS")

    response = client.post(
        "/login",
        json={
            "username": [
                NORMAL_USER,
                ADMIN_USER,
            ],
            "password": PASSWORD,
        }
    )

    expect_status(
        "Login with array username",
        response,
        422
    )


    # ============================================================
    # 13. CONFLICTING INPUT SOURCES
    # ============================================================

    print()
    print("[13] CONFLICTING INPUT SOURCES")

    response = client.post(
        "/login?username=V0816Unknown&password=wrong",
        json={
            "username": "V0816Unknown",
            "password": PASSWORD,
        }
    )

    expect_status(
        "Login with conflicting query/body values",
        response,
        401
    )


    # ============================================================
    # 14. FINAL AUTHORIZATION STABILITY
    # ============================================================

    print()
    print("[14] FINAL AUTHORIZATION STABILITY CHECK")

    response = client.get(
        "/admin/users",
        headers=normal_headers
    )

    expect_status(
        "Normal user final admin authorization check",
        response,
        403
    )

    response = client.get(
        "/admin/users",
        headers=admin_headers
    )

    expect_status(
        "Admin user final admin authorization check",
        response,
        200
    )


finally:

    print()
    print("[CLEANUP] Removing ambiguity test users and sessions")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.16 HTTP PARAMETER POLLUTION / REQUEST AMBIGUITY TEST PASSED")
else:
    print(
        f"V0.8.16 HTTP PARAMETER POLLUTION / REQUEST AMBIGUITY "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
