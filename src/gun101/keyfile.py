# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Keyfile handling for two-factor protection."""
import getpass
import hashlib
import os

# Subprocess is used solely to execute icacls with an argument list for Windows ACL enforcement
import subprocess  # nosec B404

from . import config
from ._util import safe_open_write


def _set_windows_permissions(path: str) -> None:
    """Set owner-only read/write permissions on Windows using icacls.

    Removes inherited permissions and grants read/write access solely
    to the current user. If setting permissions fails, deletes the keyfile
    and raises OSError.
    """
    try:
        try:
            username = getpass.getuser()
        except Exception:
            username = os.environ.get("USERNAME")

        if not username:
            raise OSError("Could not determine current user to set Windows keyfile permissions")

        abs_path = os.path.abspath(path)
        cmd = [
            "icacls",
            abs_path,
            "/inheritance:r",
            "/grant:r",
            f"{username}:(R,W)",
        ]
        try:
            # icacls is invoked directly with an argument list without a shell for Windows ACL configuration
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as e:
            raise OSError(f"Failed to execute icacls to secure keyfile: {e}") from None

        if result.returncode != 0 or (
            "Failed processing" in result.stdout and "Failed processing 0 files" not in result.stdout
        ):
            err_msg = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
            raise OSError(f"Failed to set secure permissions on keyfile: {err_msg}")
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _is_windows() -> bool:
    """Return True if the current operating system is Windows."""
    return os.name == "nt"


def generate_keyfile(path: str) -> None:
    """
    Generate a cryptographically random keyfile.

    Args:
        path: The filesystem path where the keyfile will be written.

    Raises:
        ValueError: If a file already exists at the given path, or if the path is unsafe.
        OSError: If creating the keyfile or securing its permissions fails.

    Side effects:
        Creates a file at `path` with owner-only permissions (0o600 on POSIX,
        restricted ACL on Windows) containing KEYFILE_LEN random bytes.
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

    if _is_windows():
        _set_windows_permissions(path)
        os.chmod(path, 0o600)
    else:
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
