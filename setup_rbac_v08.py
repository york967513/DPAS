from app.database import (
    initialize_database,
    create_role,
    create_permission,
    assign_role_to_user,
    assign_permission_to_role
)


USERNAME = "V03Test"


initialize_database()


create_role("user")
create_role("admin")


create_permission("profile.read")
create_permission("profile.write")
create_permission("users.read")
create_permission("users.delete")


assign_permission_to_role(
    "user",
    "profile.read"
)

assign_permission_to_role(
    "user",
    "profile.write"
)

assign_permission_to_role(
    "admin",
    "profile.read"
)

assign_permission_to_role(
    "admin",
    "profile.write"
)

assign_permission_to_role(
    "admin",
    "users.read"
)

assign_permission_to_role(
    "admin",
    "users.delete"
)


assign_role_to_user(
    USERNAME,
    "user"
)


print("RBAC V0.8 setup: OK")