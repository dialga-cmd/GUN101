# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Shared internal utilities for GUN-101."""
import errno
import os
import stat


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


def _same_file(first, second):
    return first.st_ino == 0 or second.st_ino == 0 or (
        first.st_ino == second.st_ino and first.st_dev == second.st_dev
    )


def _validate_open_file(fd, path, previous_stat=None):
    opened_stat = os.fstat(fd)
    if not stat.S_ISREG(opened_stat.st_mode):
        raise ValueError("Output path is not a regular file; refusing to write")
    if os.path.islink(path):
        raise ValueError("Output path is a symlink; refusing to write")

    current_stat = os.lstat(path)
    if stat.S_ISLNK(current_stat.st_mode):
        raise ValueError("Output path is a symlink; refusing to write")
    if previous_stat is not None and not _same_file(previous_stat, opened_stat):
        raise ValueError("Output path is a symlink; refusing to write")
    if not _same_file(current_stat, opened_stat):
        raise ValueError("Output path is a symlink; refusing to write")


def safe_open_write(path, force=False):
    """Open a file for writing without following a symlink during creation or replacement.
    Raises ValueError if the path is unsafe and FileExistsError if it exists without force.
    """
    validate_safe_path(path)
    binary_flag = getattr(os, "O_BINARY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_flag | nofollow_flag
    trunc_flags = os.O_WRONLY | os.O_TRUNC | binary_flag | nofollow_flag

    for _ in range(5):
        try:
            fd = os.open(path, create_flags, 0o600)
            break
        except OSError as error:
            if error.errno in (errno.ELOOP, getattr(errno, "EMLINK", None)) or os.path.islink(path):
                raise ValueError("Output path is a symlink; refusing to write") from None
            if error.errno != errno.EEXIST:
                raise

            try:
                existing_stat = os.lstat(path)
            except OSError as lstat_error:
                if lstat_error.errno == errno.ENOENT:
                    continue
                raise
            if stat.S_ISLNK(existing_stat.st_mode) or os.path.islink(path):
                raise ValueError("Output path is a symlink; refusing to write") from None
            if not stat.S_ISREG(existing_stat.st_mode):
                raise ValueError("Output path is not a regular file; refusing to write") from None
            if not force:
                raise FileExistsError(f"Output file already exists: {path}. Use --force to overwrite.") from None

            try:
                fd = os.open(path, trunc_flags, 0o600)
            except OSError as open_error:
                if open_error.errno in (errno.ELOOP, getattr(errno, "EMLINK", None)) or os.path.islink(path):
                    raise ValueError("Output path is a symlink; refusing to write") from None
                if open_error.errno == errno.ENOENT:
                    continue
                raise

            try:
                _validate_open_file(fd, path, existing_stat)
                return os.fdopen(fd, "wb")
            except Exception:
                os.close(fd)
                raise
    else:
        raise OSError("Unable to safely open file after repeated attempts")

    try:
        _validate_open_file(fd, path)
        return os.fdopen(fd, "wb")
    except Exception:
        os.close(fd)
        raise
