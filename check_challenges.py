import sqlite3


connection = sqlite3.connect(
    "data/dpas.db"
)

columns = connection.execute(
    "PRAGMA table_info(challenges)"
).fetchall()

connection.close()


print("Challenges table:")

for column in columns:
    print(
        "ID:", column[0],
        "| Name:", column[1],
        "| Type:", column[2]
    )