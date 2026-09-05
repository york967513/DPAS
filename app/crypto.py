from cryptography.hazmat.primitives import hashes, hmac


def create_response(key: bytes, challenge: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())

    h.update(challenge)

    return h.finalize()


def verify_response(
    key: bytes,
    challenge: bytes,
    response: bytes
) -> bool:

    h = hmac.HMAC(key, hashes.SHA256())

    h.update(challenge)

    try:
        h.verify(response)
        return True

    except Exception:
        return False