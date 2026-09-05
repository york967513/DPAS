from pathlib import Path


CLIENT_DATA_PATH = Path("data/client_keys")


def save_private_key(
    username: str,
    encrypted_private_key: bytes
):
    CLIENT_DATA_PATH.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path = CLIENT_DATA_PATH / f"{username}.key"

    file_path.write_bytes(
        encrypted_private_key
    )


def load_private_key(
    username: str
):
    file_path = (
        CLIENT_DATA_PATH
        / f"{username}.key"
    )

    if not file_path.exists():
        return None

    return file_path.read_bytes()