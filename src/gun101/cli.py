# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Command-line interface for GUN-101."""
import argparse
import errno
import getpass
import importlib.metadata
import os
import stat
import sys

from . import config, handler, keyfile


def get_password():
    """Get password from environment variable or prompt.
    If the environment variable GUN101_PASSWORD is set, use it (with a warning).
    Otherwise, prompt the user securely.
    """
    password = os.environ.get('GUN101_PASSWORD')
    if password is not None:
        print(
            "Warning: Using password from environment variable GUN101_PASSWORD is insecure. "
            "Consider using an interactive prompt instead.",
            file=sys.stderr
        )
        return password
    return getpass.getpass(prompt='Password: ')

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
    """Open a file for writing in binary mode, protecting against path traversal and symlink races.

    On POSIX systems, this uses os.open() with O_CREAT | O_EXCL and O_NOFOLLOW to atomically
    prevent following symlinks on creation. When overwriting an existing regular file,
    O_NOFOLLOW is used in combination with pre-open lstat() and post-open fstat() identity
    checks (comparing device and inode numbers) to prevent symlink redirection and non-regular
    file access (e.g. FIFOs, devices).

    On platforms where O_NOFOLLOW is unavailable (such as Windows), atomic symlink-rejection
    during open() is not natively supported by the operating system flags. In this case,
    the implementation uses a safe fallback: it performs preliminary symlink checks, verifies
    regular file status via pre-open lstat(), and validates file identity post-open via fstat()
    and re-checked lstat(). Residual limitation on platforms without O_NOFOLLOW: while post-open
    checks verify the file identity and close the handle if a swap occurs, a narrow race window
    theoretically exists between pre-open lstat() and os.open() where a target could be opened
    prior to verification.

    Args:
        path: Target file path to write to.

    Returns:
        A binary file object opened for writing (mode 'wb').

    Raises:
        ValueError: If the output path is a symlink, escapes the intended directory,
                    resolves to a non-regular file, or changes identity during opening.
        OSError: If an operating system error occurs during file opening.
    """
    # Preliminary symlink check
    if os.path.islink(path):
        raise ValueError("Output path is a symlink; refusing to write")

    # Path containment check
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

    binary_flag = getattr(os, "O_BINARY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    has_nofollow = hasattr(os, "O_NOFOLLOW")

    # Attempt atomic creation or safe overwrite across a bounded retry loop (to guard against
    # concurrent deletion/replacement between exclusive creation and overwrite attempts).
    for _ in range(5):
        try:
            # 1. Attempt exclusive creation first with secure permissions (0o600).
            # If the path does not exist, O_CREAT | O_EXCL atomically creates it without following symlinks.
            create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary_flag | nofollow_flag
            fd = os.open(path, create_flags, 0o600)
            break
        except OSError as e:
            if e.errno in (errno.ELOOP, getattr(errno, "EMLINK", None)) or os.path.islink(path):
                raise ValueError("Output path is a symlink; refusing to write") from None
            if e.errno == errno.EEXIST:
                # 2. File already exists: handle safe overwrite.
                try:
                    lst = os.lstat(path)
                except OSError as lst_err:
                    if lst_err.errno == errno.ENOENT:
                        continue  # File was unlinked between open and lstat; retry creation
                    raise

                if stat.S_ISLNK(lst.st_mode) or os.path.islink(path):
                    raise ValueError("Output path is a symlink; refusing to write") from None
                if not stat.S_ISREG(lst.st_mode):
                    raise ValueError("Output path is not a regular file; refusing to write") from None

                # Open existing file for truncation with O_NOFOLLOW (on platforms supporting it).
                trunc_flags = os.O_WRONLY | os.O_TRUNC | binary_flag | nofollow_flag
                try:
                    fd = os.open(path, trunc_flags, 0o600)
                except OSError as open_err:
                    if open_err.errno in (errno.ELOOP, getattr(errno, "EMLINK", None)) or os.path.islink(path):
                        raise ValueError("Output path is a symlink; refusing to write") from None
                    if open_err.errno == errno.ENOENT:
                        continue  # File unlinked between lstat and open; retry creation
                    raise

                # Verify opened fd properties against prior lstat
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        raise ValueError("Output path is not a regular file; refusing to write")
                    if os.path.islink(path):
                        raise ValueError("Output path is a symlink; refusing to write")

                    # Verify that opened file matches prior lstat (guards against swap between lstat and open)
                    if lst.st_ino != 0 and st.st_ino != 0 and (lst.st_ino != st.st_ino or lst.st_dev != st.st_dev):
                        raise ValueError("Output path is a symlink; refusing to write")

                    if not has_nofollow:
                        lst2 = os.lstat(path)
                        if stat.S_ISLNK(lst2.st_mode) or os.path.islink(path):
                            raise ValueError("Output path is a symlink; refusing to write")
                        if (
                            lst2.st_ino != 0
                            and st.st_ino != 0
                            and (lst2.st_ino != st.st_ino or lst2.st_dev != st.st_dev)
                        ):
                            raise ValueError("Output path is a symlink; refusing to write")

                    return os.fdopen(fd, "wb")
                except Exception:
                    os.close(fd)
                    raise
            else:
                raise
    else:
        raise OSError("Unable to safely open file after repeated attempts")

    # If opened via atomic exclusive creation:
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("Output path is not a regular file; refusing to write")
        if not has_nofollow:
            if os.path.islink(path):
                raise ValueError("Output path is a symlink; refusing to write")
            lst = os.lstat(path)
            if stat.S_ISLNK(lst.st_mode):
                raise ValueError("Output path is a symlink; refusing to write")
            if lst.st_ino != 0 and st.st_ino != 0 and (lst.st_ino != st.st_ino or lst.st_dev != st.st_dev):
                raise ValueError("Output path is a symlink; refusing to write")
        return os.fdopen(fd, "wb")
    except Exception:
        os.close(fd)
        raise

def encrypt(args):
    """Handle the encrypt subcommand."""
    try:
        with open(args.file, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        password = get_password()
        container = handler.encrypt_file(data, password, args.keyfile)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output if args.output else (args.file + '.gun101')
    try:
        with safe_open_write(output_path) as f:
            f.write(container)
    except (OSError, ValueError) as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Encrypted file written to: {output_path}")

def decrypt(args):
    """Handle the decrypt subcommand."""
    try:
        with open(args.file, 'rb') as f:
            container = f.read()
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        password = get_password()
        data = handler.decrypt_file(container, password, args.keyfile)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output
    if output_path is None:
        # Default: strip .gun101 extension or append .decrypted
        if args.file.endswith('.gun101'):
            output_path = args.file[:-7]  # remove .gun101
        else:
            output_path = args.file + '.decrypted'

    try:
        with safe_open_write(output_path) as f:
            f.write(data)
    except (OSError, ValueError) as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Decrypted file written to: {output_path}")

def generate_keyfile(args):
    """Handle the generate-keyfile subcommand."""
    try:
        keyfile.generate_keyfile(args.path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error creating keyfile: {e}", file=sys.stderr)
        sys.exit(1)

    # Print fingerprint for user to record
    try:
        with open(args.path, 'rb') as f:
            data = f.read()
        fingerprint = keyfile.keyfile_fingerprint(data)
        print(f"Keyfile generated at: {args.path}")
        print(f"Fingerprint (SHA-256): {fingerprint}")
    except OSError as e:
        print(f"Error reading back keyfile for fingerprint: {e}", file=sys.stderr)
        sys.exit(1)

def keyfile_fingerprint(args):
    """Handle the keyfile-fingerprint subcommand."""
    try:
        with open(args.path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(f"Error reading keyfile: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        fingerprint = keyfile.keyfile_fingerprint(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Fingerprint (SHA-256): {fingerprint}")

def info(args):
    """Handle the info subcommand."""
    def _get_pkg_version(name: str) -> str:
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return "unknown"

    fields = [
        ("protocol", config.PROTOCOL),
        ("container_version", config.CONTAINER_VERSION),
        ("argon2_time_cost", config.ARGON2_TIME_COST),
        ("argon2_memory_cost", config.ARGON2_MEMORY_COST),
        ("argon2_parallelism", config.ARGON2_PARALLELISM),
        ("argon2_hash_len", config.ARGON2_HASH_LEN),
        ("argon2_salt_len", config.ARGON2_SALT_LEN),
        ("cryptography_version", _get_pkg_version("cryptography")),
        ("argon2_cffi_version", _get_pkg_version("argon2-cffi")),
        ("password_min_length", config.PASSWORD_MIN_LENGTH),
        ("password_require_uppercase", "true" if config.PASSWORD_REQUIRE_UPPERCASE else "false"),
        ("password_require_lowercase", "true" if config.PASSWORD_REQUIRE_LOWERCASE else "false"),
        ("password_require_digit", "true" if config.PASSWORD_REQUIRE_DIGIT else "false"),
        ("password_require_special", "true" if config.PASSWORD_REQUIRE_SPECIAL else "false"),
        (
            "password_policy",
            f"min_length {config.PASSWORD_MIN_LENGTH}"
            + (", uppercase required" if config.PASSWORD_REQUIRE_UPPERCASE else "")
            + (", lowercase required" if config.PASSWORD_REQUIRE_LOWERCASE else "")
            + (", digit required" if config.PASSWORD_REQUIRE_DIGIT else "")
            + (", special character required" if config.PASSWORD_REQUIRE_SPECIAL else "")
        ),
    ]
    for key, value in fields:
        print(f"{key}={value}")

def main():
    parser = argparse.ArgumentParser(
        description="GUN-101: A simple, secure file encryption tool using "
                    "AES-256-GCM and Argon2id."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('--keyfile', help='Path to keyfile for two-factor protection')
    encrypt_parser.add_argument('--output', help='Output file path (default: input.gun101)')
    # Removed --password argument
    encrypt_parser.set_defaults(func=encrypt)

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--keyfile', help='Path to keyfile for two-factor protection')
    decrypt_parser.add_argument('--output', help='Output file path (default: strip .gun101 or add .decrypted)')
    # Removed --password argument
    decrypt_parser.set_defaults(func=decrypt)

    # Generate-keyfile subcommand
    gen_key_parser = subparsers.add_parser('generate-keyfile', help='Generate a new keyfile')
    gen_key_parser.add_argument('path', help='Path where the keyfile will be created')
    gen_key_parser.set_defaults(func=generate_keyfile)

    # Keyfile-fingerprint subcommand
    fp_parser = subparsers.add_parser('keyfile-fingerprint', help='Show fingerprint of an existing keyfile')
    fp_parser.add_argument('path', help='Path to the keyfile')
    fp_parser.set_defaults(func=keyfile_fingerprint)

    # Info subcommand
    info_parser = subparsers.add_parser('info', help='Show system and protocol configuration info')
    info_parser.set_defaults(func=info)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
