from pathlib import Path


CLIENT_DATA_PATH = Path("data/client_keys")


def _get_private_key_path(username: str) -> Path:
    CLIENT_DATA_PATH.mkdir(
        parents=True,
        exist_ok=True
    )

    client_root = CLIENT_DATA_PATH.resolve()

    candidate = (
        CLIENT_DATA_PATH
        / f"{username}.key"
    ).resolve()

    if client_root not in candidate.parents:
        raise ValueError(
            "Invalid client key path"
        )

    return candidate


def save_private_key(
    username: str,
    encrypted_private_key: bytes
):
    file_path = _get_private_key_path(
        username
    )

    file_path.write_bytes(
        encrypted_private_key
    )


def load_private_key(
    username: str
):
    file_path = _get_private_key_path(
        username
    )

    if not file_path.exists():
        return None

    return file_path.read_bytes()
