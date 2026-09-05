from app.client_storage import load_private_key
from app.key_manager import decrypt_private_key
from app.protocol import sign_challenge


def create_client_signature(
    username: str,
    password: str,
    salt: bytes,
    challenge: str
) -> str:
    """
    Load the encrypted private key from client storage,
    decrypt it using the master password,
    and sign the server challenge.
    """

    encrypted_private_key = load_private_key(
        username
    )

    if encrypted_private_key is None:
        raise ValueError(
            "Encrypted private key not found"
        )

    private_key = decrypt_private_key(
        encrypted_private_key,
        password,
        salt
    )

    signature = sign_challenge(
        private_key,
        challenge
    )

    return signature