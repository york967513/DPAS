from pathlib import Path


CLIENT_DATA_PATH = Path("data/client_keys")

_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

_WINDOWS_INVALID_CHARS = set('<>:"/\\|?*')


def _validate_username_for_filename(username: str):
    if not isinstance(username, str):
        raise ValueError(
            "Invalid client key filename"
        )

    if not username:
        raise ValueError(
            "Invalid client key filename"
        )

    if any(ord(character) < 32 for character in username):
        raise ValueError(
            "Invalid client key filename"
        )

    if any(
        character in _WINDOWS_INVALID_CHARS
        for character in username
    ):
        raise ValueError(
            "Invalid client key filename"
        )

    if username.endswith((" ", ".")):
        raise ValueError(
            "Invalid client key filename"
        )

    normalized = username.rstrip(" .")

    if normalized in {".", ".."}:
        raise ValueError(
            "Invalid client key filename"
        )

    basename = normalized.split(".", 1)[0].upper()

    if basename in _WINDOWS_RESERVED_NAMES:
        raise ValueError(
            "Invalid client key filename"
        )


def _get_private_key_path(username: str) -> Path:
    _validate_username_for_filename(
        username
    )

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
