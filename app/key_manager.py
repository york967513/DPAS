import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.password import derive_key


NONCE_LENGTH = 12


def generate_key_pair():
    """
    Generate an Ed25519 private/public key pair.
    """

    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    return private_key, public_key


def encrypt_private_key(
    private_key,
    password: str,
    salt: bytes
) -> bytes:
    """
    Encrypt an Ed25519 private key using
    a key derived from the user's master password.
    """

    encryption_key = derive_key(
        password,
        salt
    )

    private_key_bytes = private_key.private_bytes_raw()

    nonce = secrets.token_bytes(NONCE_LENGTH)

    aes = AESGCM(encryption_key)

    ciphertext = aes.encrypt(
        nonce,
        private_key_bytes,
        None
    )

    return nonce + ciphertext


def decrypt_private_key(
    encrypted_private_key: bytes,
    password: str,
    salt: bytes
):
    """
    Decrypt the Ed25519 private key.
    """

    encryption_key = derive_key(
        password,
        salt
    )

    nonce = encrypted_private_key[:NONCE_LENGTH]

    ciphertext = encrypted_private_key[NONCE_LENGTH:]

    aes = AESGCM(encryption_key)

    private_key_bytes = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    )


def get_public_key_bytes(public_key) -> bytes:
    """
    Convert public key to raw bytes.
    """

    return public_key.public_bytes_raw()