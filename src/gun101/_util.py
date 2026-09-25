# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Shared internal utilities for GUN-101."""
import os


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


def validate_safe_path(path) -> None:
    """Validate a path for safe output creation.

    Raises ValueError if the path is a symlink or escapes the current working directory.
    """
    if os.path.islink(path):
        raise ValueError("Output path is a symlink; refusing to write")

    real_path = os.path.realpath(path)
    real_cwd = os.path.realpath(os.getcwd())
    norm_path = os.path.normcase(real_path)
    norm_cwd = os.path.normcase(real_cwd)

    if _is_case_insensitive_fs(real_cwd):
        norm_path = norm_path.lower()
        norm_cwd = norm_cwd.lower()

    try:
        common_path = os.path.commonpath([norm_path, norm_cwd])
    except ValueError:
        raise ValueError("Output path attempts to escape the intended directory") from None

    if common_path != norm_cwd:
        raise ValueError("Output path attempts to escape the intended directory")


def safe_open_write(path):
    """Open a file for writing in binary mode after validating its path.
    Raises ValueError if the path is unsafe.
    """
    validate_safe_path(path)
    return open(path, 'wb')
