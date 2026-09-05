import sqlite3

connection = sqlite3.connect("C:/DPAS/data/dpas.db")

rows = connection.execute("""
SELECT
    u.username,
    r.name AS role
FROM users u
LEFT JOIN user_roles ur
    ON u.id = ur.user_id
LEFT JOIN roles r
    ON ur.role_id = r.id
ORDER BY u.id
""").fetchall()

for row in rows:
    print(row)

connection.close()
