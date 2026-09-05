from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from app.protocol import (
    create_authentication_request,
    sign_challenge,
    verify_client_response
)


USERNAME = "V03Test"


print("=== DPAS V0.3 Protocol Test ===")


# Generate client key pair
private_key = Ed25519PrivateKey.generate()

public_key = private_key.public_key()

print("Key pair generated: OK")


# Server creates authentication request
request = create_authentication_request(
    USERNAME
)

print("Authentication request created: OK")

print(
    "Username:",
    request["username"]
)

print(
    "Challenge:",
    request["challenge"]
)


# Client signs challenge
signature = sign_challenge(
    private_key,
    request["challenge"]
)

print(
    "Signature created: OK"
)

print(
    "Signature length:",
    len(signature)
)


# Server verifies signature
result = verify_client_response(
    public_key,
    request["challenge"],
    signature
)

print(
    "Correct signature verification:",
    result
)


# Test wrong challenge
second_request = create_authentication_request(
    USERNAME
)

wrong_result = verify_client_response(
    public_key,
    second_request["challenge"],
    signature
)

print(
    "Old signature with new challenge:",
    wrong_result
)


if result and not wrong_result:

    print(
        "=== V0.3 Protocol Test PASSED ==="
    )

else:

    print(
        "=== V0.3 Protocol Test FAILED ==="
    )