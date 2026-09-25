# Copyright (C) 2026 Aditya Raj
# SPDX-License-Identifier: MIT

"""High-level encryption and decryption handler."""
import base64
import hmac
import json
import os
import string
from typing import BinaryIO

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
    if len(password) < config.PASSWORD_MIN_LENGTH:
        raise ValueError("Password must be at least 10 characters long")
    if config.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if config.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if config.PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if config.PASSWORD_REQUIRE_SPECIAL and not any(c in string.punctuation for c in password):
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


class StreamingContainerReader:
    """Incremental JSON parser for GUN-101 containers with bounded memory usage."""

    def __init__(self, stream: BinaryIO, chunk_size: int = config.DEFAULT_CHUNK_SIZE):
        self.stream = stream
        self.chunk_size = chunk_size
        self.buf = bytearray()
        self.eof = False

    def _fill_buf(self, min_bytes: int = 1) -> None:
        while len(self.buf) < min_bytes and not self.eof:
            chunk = self.stream.read(self.chunk_size)
            if not chunk:
                self.eof = True
                break
            self.buf.extend(chunk)

    def _skip_whitespace(self) -> None:
        while True:
            self._fill_buf(1)
            if not self.buf:
                return
            i = 0
            while i < len(self.buf) and self.buf[i] in b" \t\r\n":
                i += 1
            if i > 0:
                del self.buf[:i]
            else:
                return

    def _peek_byte(self) -> int | None:
        self._skip_whitespace()
        if not self.buf:
            return None
        return self.buf[0]

    def _consume_byte(self, expected: int) -> None:
        self._skip_whitespace()
        if not self.buf or self.buf[0] != expected:
            raise ValueError("Decryption failed")
        del self.buf[:1]

    def _parse_string(self) -> str:
        self._consume_byte(ord(b'"'))
        str_bytes = bytearray(b'"')
        escaped = False
        while True:
            self._fill_buf(1)
            if not self.buf:
                raise ValueError("Decryption failed")
            b = self.buf.pop(0)
            str_bytes.append(b)
            if escaped:
                escaped = False
            elif b == ord(b"\\"):
                escaped = True
            elif b == ord(b'"'):
                break
        try:
            return json.loads(str_bytes.decode("utf-8"))
        except Exception:
            raise ValueError("Decryption failed") from None

    def _parse_primitive(self):
        self._skip_whitespace()
        val_bytes = bytearray()
        while True:
            self._fill_buf(1)
            if not self.buf:
                break
            b = self.buf[0]
            if b in b" \t\r\n,}":
                break
            val_bytes.append(self.buf.pop(0))
        try:
            return json.loads(val_bytes.decode("utf-8"))
        except Exception:
            raise ValueError("Decryption failed") from None

    def read_metadata_and_ciphertext_chunks(self):
        self._consume_byte(ord(b'{'))
        metadata = {}

        while True:
            b = self._peek_byte()
            if b is None:
                raise ValueError("Decryption failed")
            if b == ord(b'}'):
                self._consume_byte(ord(b'}'))
                break

            key = self._parse_string()
            self._consume_byte(ord(b':'))

            if key == "ciphertext":
                self._consume_byte(ord(b'"'))

                def ciphertext_generator():
                    b64_buf = bytearray()
                    while True:
                        self._fill_buf(self.chunk_size)
                        if not self.buf:
                            raise ValueError("Decryption failed")
                        quote_idx = -1
                        for i, ch in enumerate(self.buf):
                            if ch == ord(b'"'):
                                quote_idx = i
                                break
                        if quote_idx != -1:
                            chunk_data = self.buf[:quote_idx]
                            del self.buf[:quote_idx + 1]
                            clean_data = bytes(ch for ch in chunk_data if ch not in b" \t\r\n")
                            b64_buf.extend(clean_data)
                            if b64_buf:
                                try:
                                    ct = base64.b64decode(b64_buf)
                                except Exception:
                                    raise ValueError("Decryption failed") from None
                                if ct:
                                    yield ct
                            break
                        else:
                            data_len = len(self.buf)
                            if data_len < 4:
                                self._fill_buf(data_len + 1)
                                continue
                            take_len = data_len - (data_len % 4)
                            chunk_data = self.buf[:take_len]
                            del self.buf[:take_len]
                            clean_data = bytes(ch for ch in chunk_data if ch not in b" \t\r\n")
                            b64_buf.extend(clean_data)
                            rem = len(b64_buf) % 4
                            if rem != 0:
                                to_dec = b64_buf[:-rem]
                                b64_buf = b64_buf[-rem:]
                            else:
                                to_dec = b64_buf
                                b64_buf = bytearray()
                            if to_dec:
                                try:
                                    ct = base64.b64decode(to_dec)
                                except Exception:
                                    raise ValueError("Decryption failed") from None
                                if ct:
                                    yield ct

                def finish_parsing():
                    while True:
                        next_b = self._peek_byte()
                        if next_b is None:
                            raise ValueError("Decryption failed")
                        if next_b == ord(b'}'):
                            self._consume_byte(ord(b'}'))
                            break
                        if next_b == ord(b','):
                            self._consume_byte(ord(b','))
                            if self._peek_byte() == ord(b'}'):
                                raise ValueError("Decryption failed")
                            k = self._parse_string()
                            self._consume_byte(ord(b':'))
                            peek_val = self._peek_byte()
                            if peek_val == ord(b'"'):
                                v = self._parse_string()
                            else:
                                v = self._parse_primitive()
                            metadata[k] = v
                        else:
                            raise ValueError("Decryption failed")
                    self._skip_whitespace()
                    if self.buf or self.stream.read(1):
                        raise ValueError("Decryption failed")
                    return metadata

                return metadata, ciphertext_generator(), finish_parsing, True
            else:
                next_b = self._peek_byte()
                if next_b == ord(b'"'):
                    val = self._parse_string()
                else:
                    val = self._parse_primitive()
                metadata[key] = val

                b = self._peek_byte()
                if b == ord(b','):
                    self._consume_byte(ord(b','))
                    if self._peek_byte() == ord(b'}'):
                        raise ValueError("Decryption failed")
                elif b == ord(b'}'):
                    pass
                else:
                    raise ValueError("Decryption failed")

        return metadata, iter(()), lambda: metadata, False


def encrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    password: str,
    keyfile_path: str = None,
    chunk_size: int = config.DEFAULT_CHUNK_SIZE,
) -> None:
    """
    Encrypt streaming data with bounded memory usage.

    Args:
        in_stream: Binary input stream to read plaintext from.
        out_stream: Binary output stream to write encrypted container to.
        password: User password.
        keyfile_path: Optional path to a keyfile for two-factor protection.
        chunk_size: Fixed chunk size in bytes for reading and streaming.
    """
    validate_password(password)

    salt = os.urandom(config.ARGON2_SALT_LEN)
    keyfile_bytes = None
    if keyfile_path is not None:
        keyfile_bytes = keyfile.load_keyfile(keyfile_path)

    key = kdf.derive_key(password, salt, keyfile_bytes)
    nonce = os.urandom(config.AES_NONCE_LEN)

    header = {
        "protocol": config.PROTOCOL,
        "version": "2.1",
        "keyfile_required": keyfile_path is not None,
        "keyfile_fingerprint": keyfile.keyfile_fingerprint(keyfile_bytes) if keyfile_bytes else None,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
    }
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    header_bytes = header_json.encode("utf-8")

    encryptor = cipher.StreamEncryptor(key, nonce, header_bytes)
    key = bytes(config.AES_KEY_LEN)
    del key

    prefix = (
        '{"protocol": '
        + json.dumps(header["protocol"])
        + ', "version": '
        + json.dumps(header["version"])
        + ', "keyfile_required": '
        + json.dumps(header["keyfile_required"])
        + ', "keyfile_fingerprint": '
        + json.dumps(header["keyfile_fingerprint"])
        + ', "salt": '
        + json.dumps(header["salt"])
        + ', "nonce": '
        + json.dumps(header["nonce"])
        + ', "ciphertext": "'
    )
    out_stream.write(prefix.encode("utf-8"))

    leftover = b""
    while True:
        chunk = in_stream.read(chunk_size)
        if not chunk:
            break
        ct = encryptor.update(chunk)
        buf = leftover + ct
        rem = len(buf) % 3
        if rem != 0:
            to_encode = buf[:-rem]
            leftover = buf[-rem:]
        else:
            to_encode = buf
            leftover = b""
        if to_encode:
            out_stream.write(base64.b64encode(to_encode))

    final_ct, tag = encryptor.finalize()
    buf = leftover + final_ct
    if buf:
        out_stream.write(base64.b64encode(buf))

    tag_b64 = base64.b64encode(tag).decode("utf-8")
    suffix = '", "tag": "' + tag_b64 + '"}'
    out_stream.write(suffix.encode("utf-8"))


def decrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    password: str,
    keyfile_path: str = None,
    chunk_size: int = config.DEFAULT_CHUNK_SIZE,
) -> None:
    """
    Decrypt streaming container data with bounded memory usage.

    Args:
        in_stream: Binary input stream to read encrypted container from.
        out_stream: Binary output stream to write decrypted plaintext to.
        password: User password.
        keyfile_path: Optional path to keyfile.
        chunk_size: Fixed chunk size in bytes for reading and streaming.

    Raises:
        ValueError: On any error or authentication failure.
    """
    reader = StreamingContainerReader(in_stream, chunk_size=chunk_size)
    meta, ct_gen, finish_meta, saw_ciphertext = reader.read_metadata_and_ciphertext_chunks()

    if not saw_ciphertext:
        raise ValueError("Decryption failed")

    if meta.get("protocol") != config.PROTOCOL:
        raise ValueError("Decryption failed")
    version = meta.get("version")
    if version not in ("2.0", "2.1"):
        raise ValueError("Decryption failed")

    keyfile_required = meta.get("keyfile_required", False)
    if keyfile_required and keyfile_path is None:
        raise ValueError("Decryption failed")

    keyfile_bytes = None
    if keyfile_path is not None:
        keyfile_bytes = keyfile.load_keyfile(keyfile_path)
        expected_fingerprint = meta.get("keyfile_fingerprint")
        if not isinstance(expected_fingerprint, str):
            raise ValueError("Decryption failed")
        actual_fingerprint = keyfile.keyfile_fingerprint(keyfile_bytes)
        if not hmac.compare_digest(actual_fingerprint.encode("utf-8"), expected_fingerprint.encode("utf-8")):
            raise ValueError("Decryption failed")

    try:
        salt = base64.b64decode(meta["salt"])
        nonce = base64.b64decode(meta["nonce"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("Decryption failed") from None

    if len(salt) != config.ARGON2_SALT_LEN or len(nonce) != config.AES_NONCE_LEN:
        raise ValueError("Decryption failed")

    key = kdf.derive_key(password, salt, keyfile_bytes)

    if version == "2.0":
        header_bytes = None
    else:  # version == "2.1"
        header_for_aad = meta.copy()
        header_for_aad.pop("ciphertext", None)
        header_for_aad.pop("tag", None)
        header_json = json.dumps(header_for_aad, separators=(",", ":"), sort_keys=True)
        header_bytes = header_json.encode("utf-8")

    tag_b64 = meta.get("tag")
    tag = None
    if tag_b64 is not None:
        try:
            tag = base64.b64decode(tag_b64)
        except Exception:
            raise ValueError("Decryption failed") from None
        if len(tag) != 16:
            raise ValueError("Decryption failed")

    decryptor = cipher.StreamDecryptor(key, nonce, tag=tag, associated_data=header_bytes)
    key = bytes(config.AES_KEY_LEN)
    del key

    try:
        for ct_chunk in ct_gen:
            pt = decryptor.update(ct_chunk)
            if pt:
                out_stream.write(pt)

        final_meta = finish_meta()
        if tag is None:
            tag_b64 = final_meta.get("tag")
            if not tag_b64 or not isinstance(tag_b64, str):
                raise ValueError("Decryption failed")
            try:
                tag = base64.b64decode(tag_b64)
            except Exception:
                raise ValueError("Decryption failed") from None
            if len(tag) != 16:
                raise ValueError("Decryption failed")

        final_pt = decryptor.finalize(tag)
        if final_pt:
            out_stream.write(final_pt)
    except Exception:
        raise ValueError("Decryption failed") from None


encrypt_file_stream = encrypt_stream
decrypt_file_stream = decrypt_stream
