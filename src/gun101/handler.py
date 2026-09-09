# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""High-level encryption and decryption handler."""
import base64
import hmac
import json
import os
import string

from . import cipher, config, kdf, keyfile


def validate_password(password: str) -> None:
    """
    Validate password strength.

    Args:
        password: The password to validate.

    Raises:
        ValueError: If the password does not meet strength requirements.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string")
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(c in string.punctuation for c in password):
        raise ValueError("Password must contain at least one special character")


def encrypt_file(file_data: bytes, password: str, keyfile_path: str = None) -> bytes:
    """
    Encrypt file data with optional keyfile for two-factor protection.

    Args:
        file_data: The file content to encrypt (bytes).
        password: The user password (must be at least 10 characters with uppercase,
        lowercase, digit, and special character).
        keyfile_path: Optional path to a keyfile for two-factor mode.

    Returns:
        Encrypted container as UTF-8 encoded JSON bytes.

    Steps:
        1. Validate inputs.
        2. Generate random salt.
        3. Load keyfile if provided.
        4. Derive encryption key using Argon2id.
        5. Generate nonce.
        6. Build header for v2.1 (authenticated header).
        7. Encrypt data with AES-256-GCM (with authenticated header for v2.1).
        8. Wipe key from memory.
        9. Build JSON container with metadata.
    """
    # Input validation
    if not isinstance(file_data, bytes):
        raise ValueError("File data must be bytes")
    validate_password(password)

    # Step 2: Generate salt
    salt = os.urandom(config.ARGON2_SALT_LEN)

    # Step 3: Load keyfile if provided
    keyfile_bytes = None
    if keyfile_path is not None:
        keyfile_bytes = keyfile.load_keyfile(keyfile_path)

    # Step 4: Derive key
    key = kdf.derive_key(password, salt, keyfile_bytes)

    # Step 5: Generate nonce
    nonce = os.urandom(config.AES_NONCE_LEN)

    # Build header for v2.1 (authenticated header)
    header = {
        "protocol": config.PROTOCOL,
        "version": "2.1",  # We always encrypt with the new version
        "keyfile_required": keyfile_path is not None,
        "keyfile_fingerprint": keyfile.keyfile_fingerprint(keyfile_bytes) if keyfile_bytes else None,
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8')
    }
    # Convert header to JSON bytes for associated data (with sorted keys for deterministic ordering)
    header_json = json.dumps(header, separators=(',', ':'), sort_keys=True)  # Compact JSON
    header_bytes = header_json.encode('utf-8')

    # Encrypt with associated data
    ciphertext, tag = cipher.encrypt(file_data, key, nonce, header_bytes)

    # Step 6: Wipe key from memory (overwrite with zeros and delete reference)
    key = bytes(config.AES_KEY_LEN)  # Overwrite with zeros
    del key

    # Step 7: Build container (header + ciphertext + tag)
    container = header.copy()
    container["ciphertext"] = base64.b64encode(ciphertext).decode('utf-8')
    container["tag"] = base64.b64encode(tag).decode('utf-8')
    return json.dumps(container).encode('utf-8')


def decrypt_file(container_data: bytes, password: str, keyfile_path: str = None) -> bytes:
    """
    Decrypt container data with optional keyfile.

    Args:
        container_data: The encrypted container (JSON bytes).
        password: The user password.
        keyfile_path: Optional path to keyfile (required if container indicates keyfile_required).

    Returns:
        Decrypted file data as bytes.

    Raises:
        ValueError: For any error (malformed container, wrong password, missing/wrong keyfile, etc.).
    """
    # Step 1: Parse JSON
    if not isinstance(container_data, bytes):
        raise ValueError("Decryption failed")
    try:
        container = json.loads(container_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Decryption failed") from None

    if not isinstance(container, dict):
        raise ValueError("Decryption failed")

    # Step 2: Verify protocol and version
    if container.get("protocol") != config.PROTOCOL:
        raise ValueError("Decryption failed")
    version = container.get("version")
    if version not in ("2.0", "2.1"):
        raise ValueError("Decryption failed")

    # Step 3: Check if keyfile is required
    keyfile_required = container.get("keyfile_required", False)
    if keyfile_required and keyfile_path is None:
        raise ValueError("Decryption failed")

    # Step 4: If keyfile provided, verify fingerprint
    keyfile_bytes = None
    if keyfile_path is not None:
        keyfile_bytes = keyfile.load_keyfile(keyfile_path)
        expected_fingerprint = container.get("keyfile_fingerprint")
        if not isinstance(expected_fingerprint, str):
            raise ValueError("Decryption failed")
        actual_fingerprint = keyfile.keyfile_fingerprint(keyfile_bytes)
        if not hmac.compare_digest(actual_fingerprint.encode('utf-8'), expected_fingerprint.encode('utf-8')):
            raise ValueError("Decryption failed")

    # Step 5: Decode salt, nonce, ciphertext, tag
    try:
        salt = base64.b64decode(container["salt"])
        nonce = base64.b64decode(container["nonce"])
        ciphertext = base64.b64decode(container["ciphertext"])
        tag = base64.b64decode(container["tag"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("Decryption failed") from None

    # Step 6: Derive key
    key = kdf.derive_key(password, salt, keyfile_bytes)

    # Step 7: Decrypt
    try:
        if version == "2.0":
            # Old format: no associated data
            plaintext = cipher.decrypt(nonce, ciphertext, tag, key, None)
        else:  # version == "2.1"
            # New format: authenticated header
            # Create a copy of the container without the ciphertext and tag for associated data
            header_for_aad = container.copy()
            header_for_aad.pop("ciphertext", None)
            header_for_aad.pop("tag", None)
            header_json = json.dumps(header_for_aad, separators=(',', ':'), sort_keys=True)  # Compact JSON
            header_bytes = header_json.encode('utf-8')
            plaintext = cipher.decrypt(nonce, ciphertext, tag, key, header_bytes)
    except Exception:
        # Any error (invalid tag, wrong key, etc.) results in a generic error
        raise ValueError("Decryption failed") from None
    finally:
        # Wipe key from memory
        key = bytes(config.AES_KEY_LEN)  # Overwrite with zeros
        del key

    return plaintext
