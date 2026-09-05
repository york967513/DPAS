import base64
import json

from app.challenge import generate_challenge
from app.crypto import create_response, verify_response
from app.password import derive_key


def create_authentication_request(username: str) -> dict:
    challenge = generate_challenge()

    return {
        "username": username,
        "challenge": base64.b64encode(challenge).decode("ascii")
    }


def create_client_response(
    password: str,
    salt: bytes,
    challenge: str
) -> str:

    challenge_bytes = base64.b64decode(challenge)

    key = derive_key(password, salt)

    response = create_response(
        key,
        challenge_bytes
    )

    return base64.b64encode(response).decode("ascii")


def verify_client_response(
    key: bytes,
    challenge: str,
    response: str
) -> bool:

    challenge_bytes = base64.b64decode(challenge)
    response_bytes = base64.b64decode(response)

    return verify_response(
        key,
        challenge_bytes,
        response_bytes
    )