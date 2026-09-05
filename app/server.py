import sqlite3
import secrets

from app.database import get_connection
from app.crypto import verify_response


CHALLENGE_LENGTH = 32


class AuthenticationServer:

    def __init__(self):
        self.active_challenges = {}

    def start_authentication(self, username: str):

        connection = get_connection()

        user = connection.execute(
            """
            SELECT id, username, auth_salt
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user is None:
            return None

        challenge = secrets.token_bytes(CHALLENGE_LENGTH)

        self.active_challenges[username] = challenge

        return {
            "username": username,
            "challenge": challenge
        }

    def verify_authentication(
        self,
        username: str,
        response: bytes,
        key: bytes
    ) -> bool:

        challenge = self.active_challenges.get(username)

        if challenge is None:
            return False

        valid = verify_response(
            key,
            challenge,
            response
        )

        # Challenge can only be used once
        del self.active_challenges[username]

        return valid