from app.database import assign_role_to_user

result = assign_role_to_user(
    "V03Test",
    "admin"
)

print("Admin role assigned:", result)
