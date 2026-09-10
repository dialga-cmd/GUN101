# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Keyfile handling for two-factor protection."""
import hashlib
import os

from . import config


def _is_case_insensitive_fs(path: str) -> bool:
    """Determine whether the filesystem hosting `path` is case-insensitive.

    Performs a safe, read-only check: tests whether alternating the case of
    an existing path component resolves to the exact same file/directory on disk
    via os.path.exists() and os.path.samefile().
    """
    if os.name == "nt":
        return True
    try:
        cur = path
        while cur and cur != os.path.dirname(cur):
            base = os.path.basename(cur)
            parent = os.path.dirname(cur)
            for i, ch in enumerate(base):
                if ch.isalpha():
                    alt_base = base[:i] + (ch.lower() if ch.isupper() else ch.upper()) + base[i + 1:]
                    alt_path = os.path.join(parent, alt_base)
                    return os.path.exists(alt_path) and os.path.samefile(cur, alt_path)
            cur = parent
    except OSError:
        pass
    return False


def safe_open_write(path):
    """Open a file for writing in binary mode, after checking for symlinks and path safety.
    Raises ValueError if the path is unsafe.
    """
    # Check for symlink on the given path (before resolving)
    if os.path.islink(path):
        raise ValueError("Output path is a symlink; refusing to write")

    # Get the real path (resolving symlinks)
    real_path = os.path.realpath(path)
    real_cwd = os.path.realpath(os.getcwd())
    norm_path = os.path.normcase(real_path)
    norm_cwd = os.path.normcase(real_cwd)

    # If the underlying filesystem is case-insensitive (e.g. Windows NTFS, or default APFS
    # on macOS where posixpath.normcase() is a no-op), fold case before commonpath containment check.
    if _is_case_insensitive_fs(real_cwd):
        norm_path = norm_path.lower()
        norm_cwd = norm_cwd.lower()

    try:
        common_path = os.path.commonpath([norm_path, norm_cwd])
    except ValueError:
        raise ValueError("Output path attempts to escape the intended directory") from None

    # Ensure the real path is within the real cwd
    if common_path != norm_cwd:
        raise ValueError("Output path attempts to escape the intended directory")

    # Open the file for writing in binary mode
    return open(path, 'wb')

def generate_keyfile(path: str) -> None:
    """
    Generate a cryptographically random keyfile.

    Args:
        path: The filesystem path where the keyfile will be written.

    Raises:
        ValueError: If a file already exists at the given path, or if the path is unsafe.

    Side effects:
        Creates a file at `path` with 0o600 permissions containing
        KEYFILE_LEN random bytes.
    """
    if os.path.exists(path):
        raise ValueError(f"Key file already exists at {path}. "
                         "Delete it manually if you intend to replace it.")
    keyfile_bytes = os.urandom(config.KEYFILE_LEN)
    try:
        with safe_open_write(path) as f:
            f.write(keyfile_bytes)
    except OSError as e:
        raise OSError(f"Error creating keyfile: {e}") from None
    # Restrict permissions to owner read/write only
    os.chmod(path, 0o600)

def load_keyfile(path: str) -> bytes:
    """
    Load a keyfile from disk.

    Args:
        path: Path to the keyfile.

    Returns:
        The keyfile bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not exactly KEYFILE_LEN bytes.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file not found: {path}")
    with open(path, 'rb') as f:
        data = f.read()
    if len(data) != config.KEYFILE_LEN:
        raise ValueError(f"Key file must be {config.KEYFILE_LEN} bytes long")
    return data

def keyfile_fingerprint(keyfile_bytes: bytes) -> str:
    """
    Compute a SHA-256 fingerprint of the keyfile bytes.

    Args:
        keyfile_bytes: The keyfile bytes (must be KEYFILE_LEN bytes).

    Returns:
        A hexadecimal string of length 64 (SHA-256 digest).
    """
    if not isinstance(keyfile_bytes, bytes) or len(keyfile_bytes) != config.KEYFILE_LEN:
        raise ValueError(f"Keyfile must be {config.KEYFILE_LEN} bytes")
    return hashlib.sha256(keyfile_bytes).hexdigest()
