import ctypes
import os
import stat
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


if os.name == "nt":
    import msvcrt
    from ctypes import wintypes

    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True
    )

    _GetFileInformationByHandle = (
        _kernel32.GetFileInformationByHandle
    )

    _GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]

    _GetFileInformationByHandle.restype = wintypes.BOOL

    _GetFinalPathNameByHandleW = (
        _kernel32.GetFinalPathNameByHandleW
    )

    _GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]

    _GetFinalPathNameByHandleW.restype = wintypes.DWORD


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


def _get_final_path_from_fd(file_descriptor: int) -> Path:
    if os.name != "nt":
        proc_path = Path(
            f"/proc/self/fd/{file_descriptor}"
        )

        if proc_path.exists():
            return Path(
                os.path.realpath(proc_path)
            )

        raise RuntimeError(
            "Final file path is unavailable"
        )

    handle = msvcrt.get_osfhandle(
        file_descriptor
    )

    buffer_size = 260

    while True:
        buffer = ctypes.create_unicode_buffer(
            buffer_size
        )

        result = _GetFinalPathNameByHandleW(
            handle,
            buffer,
            buffer_size,
            0
        )

        if result == 0:
            error_code = ctypes.get_last_error()
            raise OSError(
                error_code,
                "GetFinalPathNameByHandleW failed"
            )

        if result < buffer_size:
            final_path = buffer.value
            break

        buffer_size = result + 1

    if final_path.startswith(
        "\\\\?\\UNC\\"
    ):
        final_path = (
            "\\\\"
            + final_path[8:]
        )

    elif final_path.startswith(
        "\\\\?\\"
    ):
        final_path = final_path[4:]

    return Path(final_path)


def _get_handle_information(
    file_descriptor: int
):
    if os.name != "nt":
        file_stat = os.fstat(
            file_descriptor
        )

        return (
            file_stat.st_nlink,
            False,
            stat.S_ISDIR(file_stat.st_mode),
        )

    handle = msvcrt.get_osfhandle(
        file_descriptor
    )

    information = _BY_HANDLE_FILE_INFORMATION()

    result = _GetFileInformationByHandle(
        handle,
        ctypes.byref(information)
    )

    if not result:
        error_code = ctypes.get_last_error()
        raise OSError(
            error_code,
            "GetFileInformationByHandle failed"
        )

    return (
        information.nNumberOfLinks,
        bool(
            information.dwFileAttributes
            & FILE_ATTRIBUTE_REPARSE_POINT
        ),
        bool(
            information.dwFileAttributes
            & FILE_ATTRIBUTE_DIRECTORY
        ),
    )


def _validate_open_private_key(
    file_descriptor: int,
    client_root: Path
):
    link_count, is_reparse_point, is_directory = (
        _get_handle_information(
            file_descriptor
        )
    )

    if is_directory:
        raise ValueError(
            "Invalid client key file"
        )

    if is_reparse_point:
        raise ValueError(
            "Invalid client key file"
        )

    if link_count > 1:
        raise ValueError(
            "Invalid client key file"
        )

    final_path = _get_final_path_from_fd(
        file_descriptor
    )

    root_text = os.path.normcase(
        str(client_root)
    )

    final_text = os.path.normcase(
        str(final_path)
    )

    try:
        common_path = os.path.commonpath(
            [
                root_text,
                final_text,
            ]
        )
    except ValueError:
        raise ValueError(
            "Invalid client key path"
        )

    if common_path != root_text:
        raise ValueError(
            "Invalid client key path"
        )


def _open_existing_private_key(
    file_path: Path,
    flags: int
):
    try:
        return os.open(
            file_path,
            flags
        )
    except FileNotFoundError:
        return None


def _open_new_private_key(
    file_path: Path,
    flags: int
):
    try:
        return os.open(
            file_path,
            flags | os.O_CREAT | os.O_EXCL,
            0o600
        )
    except FileExistsError:
        return None


def _read_all(
    file_descriptor: int
) -> bytes:
    chunks = []

    while True:
        chunk = os.read(
            file_descriptor,
            1024 * 1024
        )

        if not chunk:
            break

        chunks.append(chunk)

    return b"".join(chunks)


def _write_all(
    file_descriptor: int,
    data: bytes
):
    os.ftruncate(
        file_descriptor,
        0
    )

    os.lseek(
        file_descriptor,
        0,
        os.SEEK_SET
    )

    offset = 0
    total = len(data)

    while offset < total:
        written = os.write(
            file_descriptor,
            data[offset:]
        )

        if written <= 0:
            raise OSError(
                "Failed to write client key"
            )

        offset += written

    os.fsync(
        file_descriptor
    )


def save_private_key(
    username: str,
    encrypted_private_key: bytes
):
    file_path = _get_private_key_path(
        username
    )

    client_root = CLIENT_DATA_PATH.resolve()

    binary_flag = getattr(
        os,
        "O_BINARY",
        0
    )

    flags = (
        os.O_RDWR
        | binary_flag
    )

    file_descriptor = _open_existing_private_key(
        file_path,
        flags
    )

    if file_descriptor is None:
        file_descriptor = _open_new_private_key(
            file_path,
            flags
        )

    if file_descriptor is None:
        file_descriptor = _open_existing_private_key(
            file_path,
            flags
        )

    if file_descriptor is None:
        raise FileNotFoundError(
            str(file_path)
        )

    try:
        _validate_open_private_key(
            file_descriptor,
            client_root
        )

        _write_all(
            file_descriptor,
            encrypted_private_key
        )

    finally:
        os.close(
            file_descriptor
        )


def load_private_key(
    username: str
):
    file_path = _get_private_key_path(
        username
    )

    client_root = CLIENT_DATA_PATH.resolve()

    binary_flag = getattr(
        os,
        "O_BINARY",
        0
    )

    flags = (
        os.O_RDONLY
        | binary_flag
    )

    file_descriptor = _open_existing_private_key(
        file_path,
        flags
    )

    if file_descriptor is None:
        return None

    try:
        _validate_open_private_key(
            file_descriptor,
            client_root
        )

        return _read_all(
            file_descriptor
        )

    finally:
        os.close(
            file_descriptor
        )