import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from app.challenge import generate_challenge


def create_authentication_request(
    username: str
) -> dict:
    """
    Create a new authentication request.

    The server generates a fresh random challenge
    for every authentication attempt.
    """

    challenge = generate_challenge()

    return {
        "username": username,
        "challenge": base64.b64encode(
            challenge
        ).decode("ascii")
    }


def sign_challenge(
    private_key: Ed25519PrivateKey,
    challenge: str
) -> str:
    """
    Sign the server challenge using
    the client's Ed25519 private key.
    """

    challenge_bytes = base64.b64decode(
        challenge
    )

    signature = private_key.sign(
        challenge_bytes
    )

    return base64.b64encode(
        signature
    ).decode("ascii")


def verify_client_response(
    public_key: Ed25519PublicKey,
    challenge: str,
    signature: str
) -> bool:
    """
    Verify the client's signature
    against the original challenge.
    """

    challenge_bytes = base64.b64decode(
        challenge
    )

    signature_bytes = base64.b64decode(
        signature
    )

    try:

        public_key.verify(
            signature_bytes,
            challenge_bytes
        )

        return True

    except Exception:

        return False