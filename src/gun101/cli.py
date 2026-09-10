# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Command-line interface for GUN-101."""
import argparse
import getpass
import importlib.metadata
import os
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
        ("password_min_length", 10),
        ("password_require_uppercase", "true"),
        ("password_require_lowercase", "true"),
        ("password_require_digit", "true"),
        ("password_require_special", "true"),
        (
            "password_policy",
            "min_length 10, uppercase required, lowercase required, digit required, special character required",
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
