import sqlite3

from pathlib import Path
from datetime import datetime, timezone


DATABASE_PATH = Path("data/dpas.db")


def get_connection():
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=5
    )

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection


def initialize_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            auth_salt BLOB,
            public_key BLOB
        )
    """)

    columns = [
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "failed_attempts" not in columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0
        """)

    if "locked_until" not in columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN locked_until TEXT
        """)

    if "auth_salt" not in columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN auth_salt BLOB
        """)

    if "public_key" not in columns:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN public_key BLOB
        """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            challenge TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token_hash BLOB NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            FOREIGN KEY (role_id)
                REFERENCES roles(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id)
                REFERENCES roles(id)
                ON DELETE CASCADE,
            FOREIGN KEY (permission_id)
                REFERENCES permissions(id)
                ON DELETE CASCADE
        )
    """)

    # V0.9 USER MANAGEMENT

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            username TEXT,
            resource TEXT,
            details TEXT
        )
    """)

    connection.commit()
    connection.close()


def record_audit_event(
    event_type: str,
    action: str,
    result: str,
    username: str = None,
    resource: str = None,
    details: str = None
):
    connection = get_connection()

    cursor = connection.cursor()

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    cursor.execute(
        """
        INSERT INTO audit_log (
            timestamp,
            event_type,
            action,
            result,
            username,
            resource,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            event_type,
            action,
            result,
            username,
            resource,
            details
        )
    )

    connection.commit()
    connection.close()


def create_user(
    username: str,
    password_hash: str,
    auth_salt: bytes,
    public_key: bytes
):
    connection = get_connection()

    cursor = connection.cursor()

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    cursor.execute(
        """
        INSERT INTO users (
            username,
            password_hash,
            created_at,
            failed_attempts,
            locked_until,
            auth_salt,
            public_key
        )
        VALUES (?, ?, ?, 0, NULL, ?, ?)
        """,
        (
            username,
            password_hash,
            created_at,
            auth_salt,
            public_key
        )
    )

    connection.commit()
    connection.close()


def get_user(username: str):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            created_at,
            failed_attempts,
            locked_until,
            auth_salt,
            public_key
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    return user


def record_failed_attempt(username: str):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET failed_attempts = failed_attempts + 1
        WHERE username = ?
        """,
        (username,)
    )

    connection.commit()
    connection.close()


def reset_failed_attempts(username: str):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET
            failed_attempts = 0,
            locked_until = NULL
        WHERE username = ?
        """,
        (username,)
    )

    connection.commit()
    connection.close()


def lock_user(
    username: str,
    locked_until: str
):
    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET locked_until = ?
            WHERE username = ?
            """,
            (
                locked_until,
                username
            )
        )

        updated = cursor.rowcount

        if updated != 1:
            connection.rollback()
            return False

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()

    record_audit_event(
        event_type="AUTHENTICATION",
        action="ACCOUNT_LOCKED",
        result="FAILURE",
        username=username,
        resource="account",
        details="Account locked after maximum failed authentication attempts"
    )

    return True


def invalidate_active_challenges(
    username: str
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM challenges
        WHERE username = ?
          AND used = 0
        """,
        (username,)
    )

    connection.commit()

    deleted = cursor.rowcount

    connection.close()

    return deleted


def save_challenge(
    username: str,
    challenge: str
):
    connection = get_connection()

    cursor = connection.cursor()

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    cursor.execute(
        """
        INSERT INTO challenges (
            username,
            challenge,
            created_at,
            used
        )
        VALUES (?, ?, ?, 0)
        """,
        (
            username,
            challenge,
            created_at
        )
    )

    connection.commit()
    connection.close()


def get_challenge(
    username: str,
    challenge: str
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            challenge,
            created_at,
            used
        FROM challenges
        WHERE username = ?
          AND challenge = ?
        """,
        (
            username,
            challenge
        )
    )

    result = cursor.fetchone()

    connection.close()

    return result


def mark_challenge_used(
    username: str,
    challenge: str
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE challenges
        SET used = 1
        WHERE username = ?
          AND challenge = ?
          AND used = 0
        """,
        (
            username,
            challenge
        )
    )

    connection.commit()

    updated = cursor.rowcount

    connection.close()

    return updated == 1


def create_session(
    username: str,
    token_hash: bytes,
    created_at: str,
    expires_at: str
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO sessions (
            username,
            token_hash,
            created_at,
            expires_at,
            revoked
        )
        VALUES (?, ?, ?, ?, 0)
        """,
        (
            username,
            token_hash,
            created_at,
            expires_at
        )
    )

    connection.commit()
    connection.close()


def get_session(
    token_hash: bytes
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            token_hash,
            created_at,
            expires_at,
            revoked
        FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    session = cursor.fetchone()

    connection.close()

    return session


def revoke_session(
    token_hash: bytes
):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE sessions
        SET revoked = 1
        WHERE token_hash = ?
        """,
        (token_hash,)
    )

    connection.commit()

    updated = cursor.rowcount

    connection.close()

    return updated == 1


def create_role(name: str):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT OR IGNORE INTO roles (name)
        VALUES (?)
        """,
        (name,)
    )

    connection.commit()

    role_id = cursor.execute(
        """
        SELECT id
        FROM roles
        WHERE name = ?
        """,
        (name,)
    ).fetchone()[0]

    connection.close()

    return role_id


def create_permission(name: str):
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT OR IGNORE INTO permissions (name)
        VALUES (?)
        """,
        (name,)
    )

    connection.commit()

    permission_id = cursor.execute(
        """
        SELECT id
        FROM permissions
        WHERE name = ?
        """,
        (name,)
    ).fetchone()[0]

    connection.close()

    return permission_id


def assign_role_to_user(
    username: str,
    role_name: str
):
    connection = get_connection()

    cursor = connection.cursor()

    user = cursor.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    role = cursor.execute(
        """
        SELECT id
        FROM roles
        WHERE name = ?
        """,
        (role_name,)
    ).fetchone()

    if user is None or role is None:
        connection.close()
        return False

    cursor.execute(
        """
        INSERT OR IGNORE INTO user_roles (
            user_id,
            role_id
        )
        VALUES (?, ?)
        """,
        (
            user[0],
            role[0]
        )
    )

    connection.commit()
    connection.close()

    return True


def assign_permission_to_role(
    role_name: str,
    permission_name: str
):
    connection = get_connection()

    cursor = connection.cursor()

    role = cursor.execute(
        """
        SELECT id
        FROM roles
        WHERE name = ?
        """,
        (role_name,)
    ).fetchone()

    permission = cursor.execute(
        """
        SELECT id
        FROM permissions
        WHERE name = ?
        """,
        (permission_name,)
    ).fetchone()

    if role is None or permission is None:
        connection.close()
        return False

    cursor.execute(
        """
        INSERT OR IGNORE INTO role_permissions (
            role_id,
            permission_id
        )
        VALUES (?, ?)
        """,
        (
            role[0],
            permission[0]
        )
    )

    connection.commit()
    connection.close()

    return True


def user_has_permission(
    username: str,
    permission_name: str
) -> bool:

    connection = get_connection()

    cursor = connection.cursor()

    result = cursor.execute(
        """
        SELECT 1
        FROM users u
        JOIN user_roles ur
            ON u.id = ur.user_id
        JOIN roles r
            ON ur.role_id = r.id
        JOIN role_permissions rp
            ON r.id = rp.role_id
        JOIN permissions p
            ON rp.permission_id = p.id
        WHERE u.username = ?
          AND p.name = ?
        LIMIT 1
        """,
        (
            username,
            permission_name
        )
    ).fetchone()

    connection.close()

    return result is not None


def get_all_users():
    connection = get_connection()

    cursor = connection.cursor()

    users = cursor.execute(
        """
        SELECT
            id,
            username,
            created_at,
            failed_attempts,
            locked_until
        FROM users
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    return users


def delete_user(
    username: str
) -> bool:

    connection = get_connection()

    try:

        cursor = connection.cursor()

        user = cursor.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if user is None:
            return False

        user_id = user[0]

        # Remove active and expired sessions
        # belonging to the deleted user.
        cursor.execute(
            """
            DELETE FROM sessions
            WHERE username = ?
            """,
            (username,)
        )

        # Remove role assignments belonging
        # to the deleted user.
        cursor.execute(
            """
            DELETE FROM user_roles
            WHERE user_id = ?
            """,
            (user_id,)
        )

        # Keep audit_log records intentionally.
        # Audit history must survive account deletion.

        cursor.execute(
            """
            DELETE FROM users
            WHERE id = ?
            """,
            (user_id,)
        )

        deleted = cursor.rowcount

        if deleted != 1:
            connection.rollback()
            return False

        connection.commit()

        return True

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()
