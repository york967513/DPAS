import sqlite3
from pathlib import Path

DB = r"C:\DPAS\data\dpas.db"
KEY_DIR = Path(r"C:\DPAS\data\client_keys")

connection = sqlite3.connect(DB)

rows = connection.execute("""
    SELECT username, auth_salt, public_key
    FROM users
    ORDER BY id
""").fetchall()

connection.close()

print("=" * 70)
print("DPAS CLIENT KEY AUDIT")
print("=" * 70)

for username, auth_salt, public_key in rows:

    key_file = KEY_DIR / f"{username}.key"

    print()
    print("USERNAME:", username)
    print("AUTH SALT:", "PRESENT" if auth_salt else "MISSING")
    print("PUBLIC KEY:", "PRESENT" if public_key else "MISSING")
    print("PRIVATE KEY FILE:", key_file)
    print("PRIVATE KEY FILE EXISTS:", key_file.exists())

print()
print("=" * 70)
