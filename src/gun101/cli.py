# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""Command-line interface for GUN-101."""
import argparse
import getpass
import importlib.metadata
import os
import sys

from . import config, handler, keyfile
from ._util import safe_open_write, validate_safe_path


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


def encrypt(args):
    """Handle the encrypt subcommand."""
    try:
        in_f = open(args.file, 'rb')
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    password = get_password()
    try:
        handler.validate_password(password)
        if args.keyfile is not None:
            keyfile.load_keyfile(args.keyfile)
    except ValueError as e:
        in_f.close()
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        in_f.close()
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output if args.output else (args.file + '.gun101')
    force = getattr(args, 'force', False)
    try:
        out_f = safe_open_write(output_path, force=force)
    except FileExistsError as e:
        in_f.close()
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError) as e:
        in_f.close()
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with in_f, out_f:
            handler.encrypt_stream(in_f, out_f, password, args.keyfile)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        try:
            os.unlink(output_path)
        except OSError:
            pass
        sys.exit(1)
    except OSError as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        try:
            os.unlink(output_path)
        except OSError:
            pass
        sys.exit(1)

    print(f"Encrypted file written to: {output_path}")

def decrypt(args):
    """Handle the decrypt subcommand."""
    try:
        in_f = open(args.file, 'rb')
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    password = get_password()

    output_path = args.output
    if output_path is None:
        # Default: strip .gun101 extension or append .decrypted
        if args.file.endswith('.gun101'):
            output_path = args.file[:-7]  # remove .gun101
        else:
            output_path = args.file + '.decrypted'

    force = getattr(args, 'force', False)
    try:
        validate_safe_path(output_path)
    except (OSError, ValueError) as e:
        in_f.close()
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    # Stream to a temporary staging file in the target directory to prevent
    # release of unverified plaintext and ensure atomic replacement.
    temp_dir = os.path.dirname(os.path.abspath(output_path))
    temp_path = os.path.join(temp_dir, f".{os.path.basename(output_path)}.tmp.{os.urandom(8).hex()}")
    try:
        temp_f = open(temp_path, 'wb')
    except OSError as e:
        in_f.close()
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

    output_reserved = False
    try:
        with in_f, temp_f:
            handler.decrypt_stream(in_f, temp_f, password, args.keyfile)
        if not force:
            with safe_open_write(output_path):
                pass
            output_reserved = True
        os.replace(temp_path, output_path)
    except FileExistsError as e:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass
        if output_reserved:
            try:
                os.unlink(output_path)
            except OSError:
                pass
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, Exception) as e:
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError:
            pass
        if output_reserved:
            try:
                os.unlink(output_path)
            except OSError:
                pass
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
    encrypt_parser.add_argument('-f', '--force', action='store_true', help='Overwrite output file if it already exists')
    # Removed --password argument
    encrypt_parser.set_defaults(func=encrypt)

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--keyfile', help='Path to keyfile for two-factor protection')
    decrypt_parser.add_argument('--output', help='Output file path (default: strip .gun101 or add .decrypted)')
    decrypt_parser.add_argument('-f', '--force', action='store_true', help='Overwrite output file if it already exists')
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
