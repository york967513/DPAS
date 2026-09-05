from app.password import derive_key
from app.crypto import create_response


class AuthenticationClient:

    def __init__(self, username: str, password: str, salt: bytes):

        self.username = username
        self.password = password
        self.salt = salt

    def create_response(self, challenge: bytes) -> bytes:

        key = derive_key(
            self.password,
            self.salt
        )

        return create_response(
            key,
            challenge
        )