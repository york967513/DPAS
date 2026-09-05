from app.database import (
    initialize_database,
    user_has_permission
)


USERNAME = "V03Test"


print("=" * 50)
print("       DPAS V0.8 RBAC TEST")
print("=" * 50)


initialize_database()


# ========================================
# USER PERMISSION
# ========================================

if user_has_permission(
    USERNAME,
    "profile.read"
):
    print("[PASS] profile.read granted")
else:
    print("[FAIL] profile.read denied")


# ========================================
# SECOND USER PERMISSION
# ========================================

if user_has_permission(
    USERNAME,
    "profile.write"
):
    print("[PASS] profile.write granted")
else:
    print("[FAIL] profile.write denied")


# ========================================
# ADMIN-ONLY PERMISSION
# ========================================

if not user_has_permission(
    USERNAME,
    "users.delete"
):
    print("[PASS] users.delete denied")
else:
    print("[FAIL] users.delete incorrectly granted")


# ========================================
# UNKNOWN PERMISSION
# ========================================

if not user_has_permission(
    USERNAME,
    "system.shutdown"
):
    print("[PASS] Unknown permission denied")
else:
    print("[FAIL] Unknown permission granted")


# ========================================
# UNKNOWN USER
# ========================================

if not user_has_permission(
    "UnknownUser",
    "profile.read"
):
    print("[PASS] Unknown user denied")
else:
    print("[FAIL] Unknown user granted access")


print()
print("=" * 50)
print("       DPAS V0.8 RBAC TEST COMPLETE")
print("=" * 50)