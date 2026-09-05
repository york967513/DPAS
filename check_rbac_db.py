import sqlite3

connection = sqlite3.connect("C:/DPAS/data/dpas.db")

for table in (
    "roles",
    "permissions",
    "user_roles",
    "role_permissions"
):
    print()
    print("=" * 40)
    print(table)
    print("=" * 40)

    rows = connection.execute(
        f"SELECT * FROM {table}"
    ).fetchall()

    for row in rows:
        print(row)

connection.close()
