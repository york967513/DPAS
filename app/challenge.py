import secrets


CHALLENGE_LENGTH = 32


def generate_challenge() -> bytes:
    """
    Generate a cryptographically secure
    random authentication challenge.
    """

    return secrets.token_bytes(
        CHALLENGE_LENGTH
    )