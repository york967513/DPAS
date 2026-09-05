import sqlite3


connection = sqlite3.connect(
    "data/dpas.db"
)

tables = connection.execute(
    """
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    """
).fetchall()

connection.close()


print("Database tables:")

for table in tables:
    print("-", table[0])