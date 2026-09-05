import os
from app.key_manager import (
    generate_key_pair,
    encrypt_private_key,
    decrypt_private_key,
    get_public_key_bytes
)


PASSWORD = os.getenv("DPAS_TEST_PASSWORD", "DPAS_Test_Password_2026!")

SALT = b"0123456789abcdef"


print("=== DPAS V0.3 Key Test ===")


# Generate key pair
private_key, public_key = generate_key_pair()

print("Key pair generated: OK")


# Encrypt private key
encrypted = encrypt_private_key(
    private_key,
    PASSWORD,
    SALT
)

print("Encrypted private key length:", len(encrypted))


# Decrypt private key
decrypted_private_key = decrypt_private_key(
    encrypted,
    PASSWORD,
    SALT
)

print("Private key decrypted: OK")


# Compare public keys
original_public = get_public_key_bytes(
    public_key
)

decrypted_public = get_public_key_bytes(
    decrypted_private_key.public_key()
)


print(
    "Public keys identical:",
    original_public == decrypted_public
)
