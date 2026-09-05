from urllib.parse import urlparse

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


NORMAL_USER = "V0815Normal"
ADMIN_USER = "V0815Admin"
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


def check_not_admin_data(label, response):
    if response.status_code == 200:
        try:
            body = response.json()
        except Exception:
            fail_check(
                label,
                "HTTP 200 response was not valid JSON"
            )
            return

        if (
            isinstance(body, dict)
            and body.get("permission") == "users.read"
        ):
            fail_check(
                label,
                "admin users.read response was exposed"
            )
        elif (
            isinstance(body, dict)
            and isinstance(body.get("users"), list)
        ):
            fail_check(
                label,
                "admin users list was exposed"
            )
        else:
            pass_check(
                f"{label} -> HTTP 200 without admin data"
            )
    else:
        pass_check(
            f"{label} -> HTTP {response.status_code}"
        )


try:

    # ============================================================
    # SETUP
    # ============================================================

    print("=" * 70)
    print("DPAS V0.8.15 API ROUTING / URL MANIPULATION TEST")
    print("=" * 70)

    print()
    print("[SETUP] Creating isolated routing test users")

    cleanup()

    create_user(NORMAL_USER)
    create_user(ADMIN_USER)
    add_admin_role(ADMIN_USER)

    normal_token = create_user_session(NORMAL_USER)
    admin_token = create_user_session(ADMIN_USER)

    pass_check("Routing test sessions created")

    normal_headers = {
        "Authorization": f"Bearer {normal_token}"
    }

    admin_headers = {
        "Authorization": f"Bearer {admin_token}"
    }


    # ============================================================
    # 1. CANONICAL ROUTES
    # ============================================================

    print()
    print("[1] CANONICAL ROUTES")

    response = client.get("/health")
    expect_status(
        "GET /health",
        response,
        200
    )

    response = client.get(
        "/session",
        headers=normal_headers
    )

    expect_status(
        "GET /session",
        response,
        200
    )

    response = client.get(
        "/protected/profile",
        headers=normal_headers
    )

    expect_status(
        "GET /protected/profile",
        response,
        200
    )

    response = client.get(
        "/admin/users",
        headers=admin_headers
    )

    expect_status(
        "Admin GET /admin/users",
        response,
        200
    )


    # ============================================================
    # 2. TRAILING SLASH
    # ============================================================

    print()
    print("[2] TRAILING SLASH NORMALIZATION")

    response = client.get(
        "/session/",
        headers=normal_headers
    )

    if response.status_code == 200:
        if response.json().get("username") == NORMAL_USER:
            pass_check(
                "GET /session/ preserved normal-user identity"
            )
        else:
            fail_check(
                "GET /session/ identity",
                "unexpected username"
            )
    elif response.status_code in (
        301,
        302,
        307,
        308,
        404,
    ):
        pass_check(
            f"GET /session/ did not bypass authorization "
            f"(HTTP {response.status_code})"
        )
    else:
        fail_check(
            "GET /session/",
            f"unexpected HTTP {response.status_code}"
        )

    response = client.get(
        "/admin/users/",
        headers=normal_headers
    )

    if response.status_code == 403:
        pass_check(
            "Normal user denied /admin/users/"
        )
    elif response.status_code in (404, 405):
        pass_check(
            f"Normal user could not reach admin resource "
            f"through trailing slash (HTTP {response.status_code})"
        )
    else:
        fail_check(
            "Normal user -> /admin/users/",
            f"possible admin authorization bypass: "
            f"HTTP {response.status_code}"
        )


    # ============================================================
    # 3. REDIRECT TARGET
    # ============================================================

    print()
    print("[3] REDIRECT TARGET VALIDATION")

    redirect_paths = [
        "/session/",
        "/protected/profile/",
        "/admin/users/",
    ]

    for path in redirect_paths:

        response = client.get(
            path,
            headers=normal_headers,
            follow_redirects=False
        )

        if response.status_code in (
            200,
            403,
            404,
            405,
        ):
            pass_check(
                f"{path} resolved without redirect "
                f"(HTTP {response.status_code})"
            )

        elif response.status_code in (
            301,
            302,
            307,
            308,
        ):

            location = response.headers.get(
                "location",
                ""
            )

            parsed = urlparse(location)

            if (
                not parsed.netloc
                or parsed.netloc == "testserver"
            ):
                pass_check(
                    f"{path} redirects to local TestClient path: "
                    f"{location}"
                )
            else:
                fail_check(
                    f"{path} redirect target",
                    f"external redirect detected: {location}"
                )

        else:
            fail_check(
                f"{path} redirect behaviour",
                f"unexpected HTTP {response.status_code}"
            )


    # ============================================================
    # 4. DOUBLE SLASH
    # ============================================================

    print()
    print("[4] DOUBLE-SLASH MANIPULATION")

    for path in (
        "//health",
        "/protected//profile",
        "/admin//users",
        "//admin//users",
    ):

        response = client.get(
            path,
            headers=normal_headers
        )

        check_not_admin_data(
            f"GET {path}",
            response
        )


    # ============================================================
    # 5. PATH TRAVERSAL-LIKE MANIPULATION
    # ============================================================

    print()
    print("[5] PATH TRAVERSAL-LIKE MANIPULATION")

    traversal_paths = [
        "/admin/users/../users",
        "/admin/users/../../users",
        "/protected/profile/../users",
        "/protected/../admin/users",
        "/admin/users/%2e%2e/%2e%2e/users",
    ]

    for path in traversal_paths:

        response = client.get(
            path,
            headers=normal_headers
        )

        check_not_admin_data(
            f"GET {path}",
            response
        )


    # ============================================================
    # 6. URL-ENCODED PATH SEPARATORS
    # ============================================================

    print()
    print("[6] URL-ENCODED PATH MANIPULATION")

    encoded_paths = [
        "/admin%2Fusers",
        "/protected%2Fprofile",
        "/admin/users%2F",
        "/session%2F",
    ]

    response = client.get(
        "/protected%2Fprofile",
        headers=normal_headers
    )

    if response.status_code == 200:
        if response.json().get("username") == NORMAL_USER:
            pass_check(
                "URL-encoded protected path preserved "
                "normal-user identity"
            )
        else:
            fail_check(
                "URL-encoded protected path identity",
                "unexpected username"
            )
    else:
        pass_check(
            "URL-encoded protected path did not bypass authorization "
            f"(HTTP {response.status_code})"
        )

    response = client.get(
        "/session%2F",
        headers=normal_headers
    )

    if response.status_code == 200:
        if response.json().get("username") == NORMAL_USER:
            pass_check(
                "URL-encoded session path preserved "
                "normal-user identity"
            )
        else:
            fail_check(
                "URL-encoded session path identity",
                "unexpected username"
            )
    else:
        pass_check(
            "URL-encoded session path did not bypass authorization "
            f"(HTTP {response.status_code})"
        )

    for path in (
        "/admin%2Fusers",
        "/admin/users%2F",
    ):

        response = client.get(
            path,
            headers=normal_headers
        )

        check_not_admin_data(
            f"GET {path}",
            response
        )


    # ============================================================
    # 7. ROUTE NAME VARIANTS
    # ============================================================

    print()
    print("[7] ROUTE NAME VARIANTS")

    variants = [
        "/ADMIN/users",
        "/Admin/users",
        "/admin/USERS",
        "/admin/users%00",
        "/admin/users.",
    ]

    for path in variants:

        response = client.get(
            path,
            headers=normal_headers
        )

        check_not_admin_data(
            f"GET {path}",
            response
        )


    # ============================================================
    # 8. ADMIN USERNAME PATH PARAMETER MANIPULATION
    # ============================================================

    print()
    print("[8] ADMIN USERNAME PATH PARAMETER MANIPULATION")

    parameter_variants = [
        "V0815Normal%2F..%2FV0815Admin",
        "..%2FV0815Admin",
        "%2E%2EV0815Admin",
        "V0815Admin%00",
        "V0815Admin.",
    ]

    for variant in parameter_variants:

        response = client.delete(
            f"/admin/users/{variant}",
            headers=normal_headers
        )

        if response.status_code in (
            403,
            404,
        ):
            pass_check(
                f"Normal user -> DELETE /admin/users/{variant} "
                f"returned HTTP {response.status_code}"
            )
        else:
            fail_check(
                f"Normal user -> DELETE /admin/users/{variant}",
                f"unexpected HTTP {response.status_code}"
            )


    # ============================================================
    # 9. CANONICAL ADMIN AUTHORIZATION
    # ============================================================

    print()
    print("[9] CANONICAL ADMIN AUTHORIZATION")

    response = client.get(
        "/admin/users",
        headers=admin_headers
    )

    expect_status(
        "Admin -> GET /admin/users",
        response,
        200
    )

    response = client.get(
        "/admin/users",
        headers=normal_headers
    )

    expect_status(
        "Normal user -> GET /admin/users",
        response,
        403
    )


    # ============================================================
    # 10. QUERY STRING MANIPULATION
    # ============================================================

    print()
    print("[10] QUERY STRING MANIPULATION")

    query_variants = [
        "/admin/users?role=admin",
        "/admin/users?permission=users.read",
        "/admin/users?authorized=true",
        "/admin/users?path=/protected/profile",
        "/admin/users?redirect=/admin/users",
    ]

    for path in query_variants:

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
    # 11. METHOD MANIPULATION
    # ============================================================

    print()
    print("[11] HTTP METHOD MANIPULATION")

    method_tests = [
        (
            "POST /admin/users",
            lambda: client.post(
                "/admin/users",
                headers=normal_headers
            )
        ),
        (
            "PUT /admin/users",
            lambda: client.put(
                "/admin/users",
                headers=normal_headers
            )
        ),
        (
            "DELETE /admin/users",
            lambda: client.delete(
                "/admin/users",
                headers=normal_headers
            )
        ),
    ]

    for label, request_fn in method_tests:

        response = request_fn()

        expect_status(
            label,
            response,
            405
        )


    # ============================================================
    # 12. UNKNOWN ADMIN-LIKE ROUTES
    # ============================================================

    print()
    print("[12] UNKNOWN ADMIN-LIKE ROUTES")

    unknown_paths = [
        "/admin",
        "/administrator/users",
        "/admin/user",
        "/admin/users/all",
        "/admin/users/list",
    ]

    for path in unknown_paths:

        response = client.get(
            path,
            headers=normal_headers
        )

        check_not_admin_data(
            f"GET {path}",
            response
        )


    # ============================================================
    # 13. ADMIN DATA EXPOSURE THROUGH VARIANTS
    # ============================================================

    print()
    print("[13] ADMIN DATA EXPOSURE THROUGH URL VARIANTS")

    admin_variant_paths = [
        "/admin/users/",
        "/admin%2Fusers",
        "/admin/users%2F",
        "/admin//users",
        "/ADMIN/users",
        "/admin/users?role=admin",
        "/admin/users?permission=users.read",
    ]

    for path in admin_variant_paths:

        response = client.get(
            path,
            headers=normal_headers
        )

        check_not_admin_data(
            f"Normal user -> {path}",
            response
        )


finally:

    print()
    print("[CLEANUP] Removing routing test users and sessions")
    cleanup()


print()
print("=" * 70)

if failures == 0:
    print("V0.8.15 API ROUTING / URL MANIPULATION TEST PASSED")
else:
    print(
        f"V0.8.15 API ROUTING / URL MANIPULATION "
        f"TEST FAILED: {failures} failure(s)"
    )

print("=" * 70)

raise SystemExit(0 if failures == 0 else 1)
